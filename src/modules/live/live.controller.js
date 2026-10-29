const crypto = require('crypto');
const { AccessToken, RoomServiceClient, TrackSource } = require('livekit-server-sdk');
const liveSessionModel = require('../../../DB/models/liveSession.model');
const liveGuestLinkModel = require('../../../DB/models/liveGuestLink.model');
const courseModel = require('../../../DB/models/course.model');
const liveRecordingModel = require('../../../DB/models/liveRecording.model');
const { getRecordingConfig, stopRoomRecording } = require('./recording.service');

// LiveClass = per-course video meetings on LiveKit. Railway needs LIVEKIT_URL (wss://...),
// LIVEKIT_API_KEY and LIVEKIT_API_SECRET; without them every endpoint answers 503.
const getConfig = () => {
    const url = process.env.LIVEKIT_URL;
    const apiKey = process.env.LIVEKIT_API_KEY;
    const apiSecret = process.env.LIVEKIT_API_SECRET;
    if (!url || !apiKey || !apiSecret) return null;
    return { url, apiKey, apiSecret, httpUrl: url.replace(/^ws/, 'http') };
};

let roomService = null;
const getRoomService = (config) => {
    if (!roomService) roomService = new RoomServiceClient(config.httpUrl, config.apiKey, config.apiSecret);
    return roomService;
};

const TOKEN_TTL = '6h';
const GUEST_TOKEN_TTL = '3h';
const STUDENT_SOURCES = [TrackSource.CAMERA, TrackSource.MICROPHONE];
const SHARE_SOURCES = [TrackSource.SCREEN_SHARE, TrackSource.SCREEN_SHARE_AUDIO];
const MAX_WAITING_GUESTS = 50;

const sameId = (a, b) => String(a) === String(b);
const hasId = (list, id) => (list || []).some((x) => sameId(x, id));
const isGuestId = (id) => String(id).startsWith('guest-');
const hashSecret = (secret) => crypto.createHash('sha256').update(String(secret)).digest('hex');
const secretMatches = (secret, hash) => {
    const a = Buffer.from(hashSecret(secret), 'hex');
    const b = Buffer.from(String(hash), 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const roomMetadata = (session) => JSON.stringify({
    courseId: String(session.course),
    hostIdentity: String(session.teacher),
    locked: session.locked,
    waitingRoom: session.waitingRoom,
    allowShare: session.allowShare,
    spotlight: session.spotlight || '',
    startedAt: session.startedAt,
    recording: !!session.recordingEgress,
    recordingStartedAt: session.recordingStartedAt || null,
    // The recorder's identity, so the host can send it the boards drawn before it joined.
    recorder: session.recordingEgress || ''
});

// role is 'host', 'student' or 'guest'. Guests get camera and microphone only, never screen share.
const createToken = async (config, session, { identity, name, role }) => {
    const isHost = role === 'host';
    const at = new AccessToken(config.apiKey, config.apiSecret, {
        identity: String(identity),
        name: name || 'Participant',
        metadata: JSON.stringify({ role }),
        ttl: role === 'guest' ? GUEST_TOKEN_TTL : TOKEN_TTL
    });
    const canShare = isHost || (role === 'student' && session.allowShare);
    at.addGrant({
        room: session.roomName,
        roomJoin: true,
        roomAdmin: isHost,
        canSubscribe: true,
        canPublish: true,
        canPublishData: true,
        canUpdateOwnMetadata: true,
        canPublishSources: canShare ? [...STUDENT_SOURCES, ...SHARE_SOURCES] : STUDENT_SOURCES
    });
    return at.toJwt();
};
const userToken = (config, session, user, role) => createToken(config, session, { identity: user._id, name: user.userName, role });

const sessionInfo = (session, course) => ({
    id: session._id,
    courseId: session.course,
    courseName: course ? course.name : undefined,
    startedAt: session.startedAt,
    locked: session.locked,
    waitingRoom: session.waitingRoom,
    allowShare: session.allowShare,
    // Whether the host may record to the cloud (a bucket is configured).
    canRecord: !!getRecordingConfig()
});

// A meeting whose LiveKit room has closed (everyone left past emptyTimeout) is marked ended,
// so "Live now" banners don't stay up forever.
const closeIfRoomGone = async (config, session) => {
    if (Date.now() - new Date(session.startedAt).getTime() < 2 * 60 * 1000) return session;
    try {
        const rooms = await getRoomService(config).listRooms([session.roomName]);
        if (rooms.length > 0) return session;
    } catch (e) {
        return session;
    }
    session.status = 'ended';
    session.endedAt = new Date();
    await session.save();
    return null;
};

const findLiveSession = async (config, courseId) => {
    const session = await liveSessionModel.findOne({ course: courseId, status: 'live' });
    if (!session) return null;
    return closeIfRoomGone(config, session);
};

const requireConfig = (res) => {
    const config = getConfig();
    if (!config) res.status(503).json({ message: 'LiveClass is not configured on this server' });
    return config;
};

// Loads the course and the caller's role in it: 'host' for the course teacher, 'student' when enrolled.
const loadCourseRole = async (req, res) => {
    const { courseId } = req.params;
    if (!/^[0-9a-fA-F]{24}$/.test(courseId)) {
        res.status(400).json({ message: 'Invalid course id' });
        return null;
    }
    const course = await courseModel.findById(courseId).select('name teacher students');
    if (!course) {
        res.status(404).json({ message: 'Course not found' });
        return null;
    }
    const userId = req.userData._id;
    if (sameId(course.teacher, userId)) return { course, role: 'host' };
    if (hasId(course.students, userId)) return { course, role: 'student' };
    res.status(403).json({ message: 'You are not part of this course' });
    return null;
};

const loadHostSession = async (req, res) => {
    const config = requireConfig(res);
    if (!config) return null;
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return null;
    if (ctx.role !== 'host') {
        res.status(403).json({ message: 'Only the host can do this' });
        return null;
    }
    const session = await findLiveSession(config, ctx.course._id);
    if (!session) {
        res.status(404).json({ message: 'This class is not live' });
        return null;
    }
    return { config, session, course: ctx.course };
};

const pushRoomMetadata = async (config, session) => {
    try {
        await getRoomService(config).updateRoomMetadata(session.roomName, roomMetadata(session));
    } catch (e) {
        // The room may not exist yet (nobody connected); clients read the flags again on join.
    }
};

const getActive = async (req, res) => {
    const config = getConfig();
    if (!config) return res.json({ message: 'success', enabled: false, live: [] });
    const userId = req.userData._id;
    const courses = await courseModel.find({ $or: [{ teacher: userId }, { students: userId }] })
        .select('name teacher')
        .populate('teacher', 'userName');
    const byId = new Map(courses.map((c) => [String(c._id), c]));
    const sessions = await liveSessionModel.find({ course: { $in: [...byId.keys()] }, status: 'live' });
    const live = [];
    for (const s of sessions) {
        const stillLive = await closeIfRoomGone(config, s);
        if (!stillLive) continue;
        const course = byId.get(String(s.course));
        live.push({
            ...sessionInfo(s, course),
            teacherName: course.teacher && course.teacher.userName,
            isHost: sameId(s.teacher, userId)
        });
    }
    res.json({ message: 'success', enabled: true, live });
};

// What the pre-join screen needs: the course name, whether the caller hosts it and whether it is live.
const getInfo = async (req, res) => {
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    const config = getConfig();
    const session = config ? await findLiveSession(config, ctx.course._id) : null;
    await ctx.course.populate('teacher', 'userName');
    res.json({
        message: 'success',
        enabled: !!config,
        courseName: ctx.course.name,
        teacherName: ctx.course.teacher && ctx.course.teacher.userName,
        role: ctx.role,
        live: !!session
    });
};

const startLive = async (req, res) => {
    const config = requireConfig(res);
    if (!config) return;
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    if (ctx.role !== 'host') return res.status(403).json({ message: 'Only the course teacher can start a LiveClass' });

    let session = await findLiveSession(config, ctx.course._id);
    if (!session) {
        session = await liveSessionModel.create({
            course: ctx.course._id,
            teacher: req.userData._id,
            roomName: `course_${ctx.course._id}_${Date.now().toString(36)}`,
            waitingRoom: req.body.waitingRoom !== false,
            allowShare: !!req.body.allowShare
        });
    }
    await getRoomService(config).createRoom({
        name: session.roomName,
        emptyTimeout: 10 * 60,
        departureTimeout: 10 * 60,
        maxParticipants: 300,
        metadata: roomMetadata(session)
    });
    const token = await userToken(config, session, req.userData, 'host');
    res.json({ message: 'success', status: 'joined', role: 'host', url: config.url, token, session: sessionInfo(session, ctx.course) });
};

// Students call this to join and keep calling it (every few seconds) while in the waiting room.
const joinLive = async (req, res) => {
    const config = requireConfig(res);
    if (!config) return;
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    const session = await findLiveSession(config, ctx.course._id);
    if (!session) return res.status(404).json({ message: 'This class is not live right now', status: 'not_live' });

    const user = req.userData;
    const info = sessionInfo(session, ctx.course);
    if (ctx.role === 'host') {
        const token = await userToken(config, session, user, 'host');
        return res.json({ message: 'success', status: 'joined', role: 'host', url: config.url, token, session: info });
    }
    if (hasId(session.removed, user._id)) {
        return res.status(403).json({ message: 'The host removed you from this meeting', status: 'removed' });
    }
    const admitted = hasId(session.admitted, user._id);
    if (session.locked && !admitted) {
        return res.status(403).json({ message: 'The host has locked this meeting', status: 'locked' });
    }
    if (session.waitingRoom && !admitted) {
        if (!session.waiting.some((w) => sameId(w.user, user._id))) {
            session.waiting.push({ user: user._id, name: user.userName });
            await session.save();
        }
        return res.json({ message: 'success', status: 'waiting', session: info });
    }
    if (!admitted) {
        session.admitted.push(user._id);
        session.waiting = session.waiting.filter((w) => !sameId(w.user, user._id));
        await session.save();
    }
    const token = await userToken(config, session, user, 'student');
    res.json({ message: 'success', status: 'joined', role: 'student', url: config.url, token, session: info });
};

const leaveWaiting = async (req, res) => {
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    await liveSessionModel.updateOne(
        { course: ctx.course._id, status: 'live' },
        { $pull: { waiting: { user: req.userData._id } } }
    );
    res.json({ message: 'success' });
};

const getWaiting = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { session } = ctx;
    const students = session.waiting.map((w) => ({ userId: w.user, name: w.name, requestedAt: w.requestedAt }));
    const guests = (session.guests || []).filter((g) => g.status === 'waiting')
        .map((g) => ({ userId: g.identity, name: g.name, requestedAt: g.requestedAt, guest: true }));
    const waiting = [...students, ...guests].sort((a, b) => new Date(a.requestedAt) - new Date(b.requestedAt));
    res.json({ message: 'success', waiting });
};

const findGuest = (session, identity) => (session.guests || []).find((g) => g.identity === String(identity));

const admit = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { session } = ctx;
    const ids = req.body.all
        ? [...session.waiting.map((w) => String(w.user)), ...(session.guests || []).filter((g) => g.status === 'waiting').map((g) => g.identity)]
        : [String(req.body.userId)];
    ids.forEach((id) => {
        if (isGuestId(id)) {
            const guest = findGuest(session, id);
            if (guest && guest.status === 'waiting') guest.status = 'admitted';
        } else if (!hasId(session.admitted, id)) {
            session.admitted.push(id);
        }
    });
    session.waiting = session.waiting.filter((w) => !ids.includes(String(w.user)));
    await session.save();
    res.json({ message: 'success' });
};

const denyWaiting = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { session } = ctx;
    const id = String(req.body.userId);
    if (isGuestId(id)) {
        const guest = findGuest(session, id);
        if (guest) guest.status = 'removed';
    } else {
        session.waiting = session.waiting.filter((w) => String(w.user) !== id);
        if (!hasId(session.removed, id)) session.removed.push(id);
    }
    await session.save();
    res.json({ message: 'success' });
};

const sharePermission = (allowShare) => ({
    canSubscribe: true,
    canPublish: true,
    canPublishData: true,
    canUpdateMetadata: true,
    canPublishSources: allowShare ? [...STUDENT_SOURCES, ...SHARE_SOURCES] : STUDENT_SOURCES
});

const updateSettings = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { session, config } = ctx;
    const shareChanged = typeof req.body.allowShare === 'boolean' && req.body.allowShare !== session.allowShare;
    ['locked', 'waitingRoom', 'allowShare'].forEach((key) => {
        if (typeof req.body[key] === 'boolean') session[key] = req.body[key];
    });
    if (typeof req.body.spotlight === 'string') session.spotlight = req.body.spotlight;
    await session.save();
    await pushRoomMetadata(config, session);

    if (shareChanged) {
        const service = getRoomService(config);
        const participants = await service.listParticipants(session.roomName).catch(() => []);
        await Promise.all(participants
            .filter((p) => !sameId(p.identity, session.teacher) && !isGuestId(p.identity))
            .map((p) => service.updateParticipant(session.roomName, p.identity, { permission: sharePermission(session.allowShare) }).catch(() => null)));
    }
    res.json({ message: 'success', session: sessionInfo(session, ctx.course) });
};

const muteTracks = async (config, session, identity, sources) => {
    const service = getRoomService(config);
    const participant = await service.getParticipant(session.roomName, identity);
    const tracks = (participant.tracks || []).filter((t) => sources.includes(t.source) && !t.muted);
    await Promise.all(tracks.map((t) => service.mutePublishedTrack(session.roomName, identity, t.sid, true)));
};

const muteParticipant = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { identity, kind } = req.body;
    const sources = kind === 'video' ? [TrackSource.CAMERA] : kind === 'screen' ? SHARE_SOURCES : [TrackSource.MICROPHONE];
    try {
        await muteTracks(ctx.config, ctx.session, String(identity), sources);
    } catch (e) {
        return res.status(404).json({ message: 'Participant not found' });
    }
    res.json({ message: 'success' });
};

const muteAll = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { config, session } = ctx;
    const participants = await getRoomService(config).listParticipants(session.roomName).catch(() => []);
    await Promise.all(participants
        .filter((p) => !sameId(p.identity, session.teacher))
        .map((p) => muteTracks(config, session, p.identity, [TrackSource.MICROPHONE]).catch(() => null)));
    res.json({ message: 'success' });
};

const removeParticipant = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { config, session } = ctx;
    const identity = String(req.body.identity);
    if (sameId(identity, session.teacher)) return res.status(400).json({ message: 'The host cannot be removed' });
    if (isGuestId(identity)) {
        const guest = findGuest(session, identity);
        if (guest) guest.status = 'removed';
    } else {
        if (!hasId(session.removed, identity)) session.removed.push(identity);
        session.admitted = session.admitted.filter((id) => !sameId(id, identity));
    }
    await session.save();
    await getRoomService(config).removeParticipant(session.roomName, identity).catch(() => null);
    res.json({ message: 'success' });
};

const endLive = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { config, session } = ctx;
    // Stop a running recording first so its file is finalised and uploaded.
    if (session.recordingEgress) {
        await stopRoomRecording(config, session.recordingEgress).catch(() => null);
        await liveRecordingModel.updateOne({ egressId: session.recordingEgress, status: 'recording' }, { status: 'processing', endedAt: new Date() });
        session.recordingEgress = '';
    }
    session.status = 'ended';
    session.endedAt = new Date();
    session.waiting = [];
    await session.save();
    await getRoomService(config).deleteRoom(session.roomName).catch(() => null);
    res.json({ message: 'success' });
};

// ---- Guest link -------------------------------------------------------------------------------
// Enrolled students join directly; anyone else with the course's guest link (parents, trial
// students, logged-in users from other courses) enters a name and always waits for the host.

const newLinkToken = () => crypto.randomBytes(18).toString('base64url');

const guestLinkInfo = (link) => ({ token: link.token, enabled: link.enabled });

const getGuestLink = async (req, res) => {
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    if (ctx.role !== 'host') return res.status(403).json({ message: 'Only the host can do this' });
    let link = await liveGuestLinkModel.findOne({ course: ctx.course._id });
    if (!link) link = await liveGuestLinkModel.create({ course: ctx.course._id, token: newLinkToken() });
    res.json({ message: 'success', link: guestLinkInfo(link) });
};

const updateGuestLink = async (req, res) => {
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    if (ctx.role !== 'host') return res.status(403).json({ message: 'Only the host can do this' });
    let link = await liveGuestLinkModel.findOne({ course: ctx.course._id });
    if (!link) link = await liveGuestLinkModel.create({ course: ctx.course._id, token: newLinkToken() });
    if (typeof req.body.enabled === 'boolean') link.enabled = req.body.enabled;
    if (req.body.regenerate === true) link.token = newLinkToken();
    await link.save();
    res.json({ message: 'success', link: guestLinkInfo(link) });
};

// Resolves /live/join/<token> to its course, or answers the request itself (404) when the link is unknown.
const loadGuestLink = async (req, res) => {
    const { token } = req.params;
    const link = /^[A-Za-z0-9_-]{16,64}$/.test(token || '') ? await liveGuestLinkModel.findOne({ token }) : null;
    const course = link ? await courseModel.findById(link.course).select('name teacher') : null;
    if (!link || !course) {
        res.status(404).json({ message: 'This invite link is not valid', status: 'invalid' });
        return null;
    }
    return { link, course };
};

// Guest names are shown to everyone in the meeting, so keep them short and printable.
const cleanGuestName = (name) => String(name || '')
    .replace(/[\u0000-\u001f\u007f<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 40);

const guestInfo = async (req, res) => {
    const ctx = await loadGuestLink(req, res);
    if (!ctx) return;
    const config = getConfig();
    const session = config ? await findLiveSession(config, ctx.course._id) : null;
    await ctx.course.populate('teacher', 'userName');
    res.json({
        message: 'success',
        enabled: !!config,
        guestsAllowed: ctx.link.enabled,
        courseId: ctx.course._id,
        courseName: ctx.course.name,
        teacherName: ctx.course.teacher && ctx.course.teacher.userName,
        live: !!session
    });
};

// Guests call this to ask in, then keep calling it with the guestId/secret it gave them while they
// wait. A LiveKit token is only handed out once the host has admitted them.
const guestJoin = async (req, res) => {
    const ctx = await loadGuestLink(req, res);
    if (!ctx) return;
    if (!ctx.link.enabled) return res.status(403).json({ message: 'The host has turned off guest access', status: 'guests_off' });
    const config = requireConfig(res);
    if (!config) return;
    const session = await findLiveSession(config, ctx.course._id);
    if (!session) return res.status(404).json({ message: 'This class is not live right now', status: 'not_live' });

    const { guestId, secret } = req.body;
    let guest = guestId && secret ? findGuest(session, guestId) : null;
    if (guest && !secretMatches(secret, guest.secretHash)) guest = null;

    if (guest && guest.status === 'removed') {
        return res.status(403).json({ message: 'The host removed you from this meeting', status: 'removed' });
    }
    if (guest && guest.status === 'admitted') {
        const token = await createToken(config, session, { identity: guest.identity, name: guest.name, role: 'guest' });
        return res.json({ message: 'success', status: 'joined', role: 'guest', url: config.url, token, session: sessionInfo(session, ctx.course) });
    }
    if (session.locked) return res.status(403).json({ message: 'The host has locked this meeting', status: 'locked' });
    if (guest) return res.json({ message: 'success', status: 'waiting' });

    const name = cleanGuestName(req.body.name);
    if (!name) return res.status(400).json({ message: 'Please enter your name', status: 'name_required' });
    if ((session.guests || []).filter((g) => g.status === 'waiting').length >= MAX_WAITING_GUESTS) {
        return res.status(429).json({ message: 'The waiting room is full, please try again later', status: 'full' });
    }
    const newSecret = crypto.randomBytes(24).toString('base64url');
    const identity = `guest-${crypto.randomBytes(8).toString('hex')}`;
    session.guests.push({ identity, name, secretHash: hashSecret(newSecret), status: 'waiting' });
    await session.save();
    res.json({ message: 'success', status: 'waiting', guestId: identity, secret: newSecret });
};

const guestLeave = async (req, res) => {
    const ctx = await loadGuestLink(req, res);
    if (!ctx) return;
    const { guestId, secret } = req.body;
    const session = await liveSessionModel.findOne({ course: ctx.course._id, status: 'live' });
    const guest = session && guestId && secret ? findGuest(session, guestId) : null;
    if (guest && guest.status === 'waiting' && secretMatches(secret, guest.secretHash)) {
        session.guests = session.guests.filter((g) => g.identity !== guest.identity);
        await session.save();
    }
    res.json({ message: 'success' });
};

module.exports = {
    getGuestLink,
    updateGuestLink,
    guestInfo,
    getConfig,
    loadCourseRole,
    loadHostSession,
    pushRoomMetadata,
    guestJoin,
    guestLeave,
    getActive,
    getInfo,
    startLive,
    joinLive,
    leaveWaiting,
    getWaiting,
    admit,
    denyWaiting,
    updateSettings,
    muteParticipant,
    muteAll,
    removeParticipant,
    endLive
};
