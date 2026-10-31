// Logged-in devices. Every token carries a session id (sid); an account keeps at most
// MAX_DEVICES sessions at once, and a login on a new device logs out the device used least
// recently. Homework opens, answers and submits are logged with the device (hwActivity) so a
// teacher can see which device a trial came from.
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const getJwtSecret = require('./jwtSecret')
const sessionModel = require('../../DB/models/session.model')
const hwActivityModel = require('../../DB/models/hwActivity.model')
const userModel = require('../../DB/models/user.model')

const MAX_DEVICES = parseInt(process.env.MAX_DEVICES, 10) || 2
// Platform staff sign in to the site and the dashboard from many places
const UNLIMITED_ROLES = ['admin', 'it', 'superadmin']
// A device not used for this long no longer takes a slot
const IDLE_MS = 30 * 24 * 60 * 60 * 1000
const TOUCH_MS = 5 * 60 * 1000
const CACHE_MS = 30 * 1000

const ENDED_MESSAGES = {
    'device-limit': `Your account was logged in on another device. An account can be used on ${MAX_DEVICES} devices at a time, so this one was logged out.`,
    staff: 'Your teacher logged this device out.',
    logout: 'You logged out on this device.',
}

const sha = (text) => crypto.createHash('sha256').update(String(text)).digest('hex')

const sessionEnded = (reason) => {
    const err = new Error(ENDED_MESSAGES[reason] || 'This device was logged out. Please log in again.')
    err.status = 401
    err.code = 'SESSION_ENDED'
    err.reason = reason || 'ended'
    return err
}

// "Windows · Chrome", "Android phone · Samsung Internet", "iPhone · Safari"
const describeUserAgent = (ua = '') => {
    let os = 'Unknown device'
    if (/iPad/i.test(ua) || (/Macintosh/i.test(ua) && /Mobile/i.test(ua))) os = 'iPad'
    else if (/iPhone|iPod/i.test(ua)) os = 'iPhone'
    else if (/Android/i.test(ua)) os = /Mobile/i.test(ua) ? 'Android phone' : 'Android tablet'
    else if (/CrOS/i.test(ua)) os = 'Chromebook'
    else if (/Windows/i.test(ua)) os = 'Windows'
    else if (/Macintosh|Mac OS X/i.test(ua)) os = 'Mac'
    else if (/Linux/i.test(ua)) os = 'Linux'

    let browser = ''
    if (/SamsungBrowser/i.test(ua)) browser = 'Samsung Internet'
    else if (/Edg\//i.test(ua)) browser = 'Edge'
    else if (/OPR\/|Opera/i.test(ua)) browser = 'Opera'
    else if (/Firefox|FxiOS/i.test(ua)) browser = 'Firefox'
    else if (/Chrome|CriOS/i.test(ua)) browser = 'Chrome'
    else if (/Safari/i.test(ua)) browser = 'Safari'
    return browser ? `${os} · ${browser}` : os
}

// The site sends a random id it keeps per browser; pages without it are told apart by browser and IP
const deviceOf = (req) => {
    const userAgent = String(req.headers['user-agent'] || '').slice(0, 400)
    const ip = req.ip || ''
    const sent = String(req.headers['x-device-id'] || '').trim()
    const deviceId = /^[A-Za-z0-9_-]{8,64}$/.test(sent) ? sent : `ua-${sha(userAgent + '|' + ip).slice(0, 20)}`
    const name = String(req.headers['x-device-name'] || '').trim().slice(0, 60)
    return { deviceId, sentId: deviceId === sent, deviceName: name || describeUserAgent(userAgent), userAgent, ip }
}

const cache = new Map()
const forget = (ids) => ids.forEach(id => cache.delete(String(id)))

const activeFilter = (userId) => ({ user: userId, endedAt: null, lastSeenAt: { $gte: new Date(Date.now() - IDLE_MS) } })

const endSessions = async (ids, reason) => {
    if (ids.length === 0) return
    await sessionModel.updateMany({ _id: { $in: ids }, endedAt: null }, { $set: { endedAt: new Date(), endedReason: reason } })
    forget(ids)
}

// Keeps the newest session plus the MAX_DEVICES - 1 most recently used others
const enforceLimit = async (user, keep) => {
    if (UNLIMITED_ROLES.includes(String(user.role || '').trim().toLowerCase())) return
    const others = await sessionModel.find({ ...activeFilter(user._id), _id: { $ne: keep._id } }).sort({ lastSeenAt: -1 }).select('_id').lean()
    await endSessions(others.slice(MAX_DEVICES - 1).map(s => s._id), 'device-limit')
}

const openSession = async (user, req, extra = {}) => {
    const device = deviceOf(req)
    // Logging in again on the same browser replaces its old session instead of taking a new slot
    if (device.sentId && !extra.legacyTokenHash) {
        const same = await sessionModel.find({ user: user._id, deviceId: device.deviceId, endedAt: null }).select('_id').lean()
        await endSessions(same.map(s => s._id), 'replaced')
    }
    const session = await sessionModel.create({
        user: user._id,
        deviceId: device.deviceId,
        deviceName: device.deviceName,
        userAgent: device.userAgent,
        ip: device.ip,
        lastSeenAt: new Date(),
        ...extra,
    })
    await enforceLimit(user, session)
    return session
}

// Use in place of jwt.sign at every login
const issueToken = async (user, req) => {
    const session = await openSession(user, req)
    return jwt.sign({ id: user._id, sid: String(session._id) }, getJwtSecret())
}

const touch = (session, req) => {
    if (Date.now() - new Date(session.lastSeenAt).getTime() < TOUCH_MS) return
    session.lastSeenAt = new Date()
    sessionModel.updateOne({ _id: session._id }, { $set: { lastSeenAt: session.lastSeenAt, ip: req.ip || session.ip } }).exec().catch(() => {})
}

const loadSession = async (filter, key) => {
    const hit = key && cache.get(key)
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.session
    const session = await sessionModel.findOne(filter).lean()
    if (session) cache.set(String(session._id), { session, at: Date.now() })
    return session
}

// A page sends many requests at once with the same old token: only one of them creates its session
const adopting = new Map()
const adoptLegacyToken = (payload, req, legacyTokenHash) => {
    if (adopting.has(legacyTokenHash)) return adopting.get(legacyTokenHash)
    const work = (async () => {
        const user = await userModel.findById(payload.id).select('role').lean()
        if (!user) return null
        try {
            return (await openSession(user, req, { legacyTokenHash })).toObject()
        } catch (err) {
            // Another server instance adopted it first (unique index)
            if (err && err.code === 11000) return sessionModel.findOne({ legacyTokenHash }).lean()
            throw err
        }
    })().finally(() => adopting.delete(legacyTokenHash))
    adopting.set(legacyTokenHash, work)
    return work
}

// Use in place of jwt.verify in the auth middleware. Returns the token payload and sets req.session.
// Throws a 401 SESSION_ENDED error when this device was logged out.
const verifySessionToken = async (req, token) => {
    const payload = jwt.verify(token, getJwtSecret())
    let session
    if (payload.sid) {
        session = await loadSession({ _id: payload.sid }, String(payload.sid))
        if (!session || String(session.user) !== String(payload.id)) throw sessionEnded()
    } else {
        // A token from before sessions: it becomes this device's session the first time it is used
        const legacyTokenHash = sha(token)
        session = await loadSession({ legacyTokenHash }, `legacy:${legacyTokenHash}`)
        if (!session) session = await adoptLegacyToken(payload, req, legacyTokenHash)
        if (!session) return payload
        cache.set(`legacy:${legacyTokenHash}`, { session, at: Date.now() })
    }
    if (session.endedAt) throw sessionEnded(session.endedReason)
    if (Date.now() - new Date(session.lastSeenAt).getTime() > IDLE_MS) throw sessionEnded('idle')
    touch(session, req)
    req.session = session
    return payload
}

const describeSession = (session, currentId) => ({
    _id: session._id,
    deviceName: session.deviceName || describeUserAgent(session.userAgent),
    ip: session.ip || '',
    loggedInAt: session.createdAt,
    lastSeenAt: session.lastSeenAt,
    endedAt: session.endedAt || null,
    endedReason: session.endedReason || null,
    current: currentId ? String(session._id) === String(currentId) : false,
})

const listSessions = async (userId, { currentId, history = 0 } = {}) => {
    const active = await sessionModel.find(activeFilter(userId)).sort({ lastSeenAt: -1 }).lean()
    const ended = history > 0
        ? await sessionModel.find({ user: userId, endedAt: { $ne: null }, endedReason: { $ne: 'replaced' } }).sort({ endedAt: -1 }).limit(history).lean()
        : []
    return {
        maxDevices: MAX_DEVICES,
        active: active.map(s => describeSession(s, currentId)),
        ended: ended.map(s => describeSession(s, currentId)),
    }
}

const endUserSession = async (userId, sessionId, reason) => {
    const session = await sessionModel.findOne({ _id: sessionId, user: userId, endedAt: null }).select('_id').lean()
    if (!session) return false
    await endSessions([session._id], reason)
    return true
}

// Logs which device opened / answered / submitted a trial. Never fails the request.
const logHwActivity = (req, { assignment, attemptNumber, action }) => {
    const student = req.userData && req.userData._id
    if (!student || !assignment) return
    const device = req.session
        ? { deviceId: req.session.deviceId, deviceName: req.session.deviceName }
        : deviceOf(req)
    const row = {
        student,
        assignment,
        attemptNumber: attemptNumber || 1,
        action,
        session: req.session ? req.session._id : undefined,
        deviceId: device.deviceId,
        deviceName: device.deviceName,
        ip: req.ip || '',
    }
    const write = action === 'answer'
        // Only the first answer saved from each device in a trial
        ? hwActivityModel.updateOne(
            { student, assignment, attemptNumber: row.attemptNumber, action, deviceId: row.deviceId },
            { $setOnInsert: { ...row, at: new Date() } },
            { upsert: true })
        : hwActivityModel.create(row)
    Promise.resolve(write).catch(err => console.warn('hwActivity log failed:', err.message))
}

// Map of "studentId:attemptNumber" -> devices that touched that trial, oldest first
const hwDevicesBy = async (assignmentId, studentIds) => {
    const filter = { assignment: assignmentId }
    if (studentIds) filter.student = { $in: studentIds }
    const rows = await hwActivityModel.find(filter).sort({ at: 1 }).lean()
    const byTrial = new Map()
    rows.forEach(r => {
        const key = `${r.student}:${r.attemptNumber || 1}`
        if (!byTrial.has(key)) byTrial.set(key, new Map())
        const devices = byTrial.get(key)
        if (!devices.has(r.deviceId)) {
            devices.set(r.deviceId, { deviceName: r.deviceName || 'Unknown device', ip: r.ip || '', firstAt: r.at, lastAt: r.at, opened: 0, answered: false, submitted: false })
        }
        const d = devices.get(r.deviceId)
        d.lastAt = r.at
        if (r.action === 'open') d.opened += 1
        if (r.action === 'answer') d.answered = true
        if (r.action === 'submit') d.submitted = true
    })
    const out = new Map()
    byTrial.forEach((devices, key) => out.set(key, [...devices.values()]))
    return out
}

module.exports = {
    MAX_DEVICES,
    describeUserAgent,
    deviceOf,
    issueToken,
    verifySessionToken,
    listSessions,
    endUserSession,
    logHwActivity,
    hwDevicesBy,
}
