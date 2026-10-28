const { AccessToken, RoomServiceClient, TrackSource } = require('livekit-server-sdk');
const liveSessionModel = require('../../../DB/models/liveSession.model');
const courseModel = require('../../../DB/models/course.model');

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
const STUDENT_SOURCES = [TrackSource.CAMERA, TrackSource.MICROPHONE];
const SHARE_SOURCES = [TrackSource.SCREEN_SHARE, TrackSource.SCREEN_SHARE_AUDIO];

const sameId = (a, b) => String(a) === String(b);
const hasId = (list, id) => (list || []).some((x) => sameId(x, id));

const roomMetadata = (session) => JSON.stringify({
    courseId: String(session.course),
    hostIdentity: String(session.teacher),
    locked: session.locked,
    waitingRoom: session.waitingRoom,
    allowShare: session.allowShare,
    spotlight: session.spotlight || '',
    startedAt: session.startedAt
});

const createToken = async (config, session, user, isHost) => {
    const at = new AccessToken(config.apiKey, config.apiSecret, {
        identity: String(user._id),
        name: user.userName || 'Participant',
        metadata: JSON.stringify({ role: isHost ? 'host' : 'student' }),
        ttl: TOKEN_TTL
    });
    at.addGrant({
        room: session.roomName,
        roomJoin: true,
        roomAdmin: isHost,
        canSubscribe: true,
        canPublish: true,
        canPublishData: true,
        canUpdateOwnMetadata: true,
        canPublishSources: isHost || session.allowShare ? [...STUDENT_SOURCES, ...SHARE_SOURCES] : STUDENT_SOURCES
    });
    return at.toJwt();
};

const sessionInfo = (session, course) => ({
    id: session._id,
    courseId: session.course,
    courseName: course ? course.name : undefined,
    startedAt: session.startedAt,
    locked: session.locked,
    waitingRoom: session.waitingRoom,
    allowShare: session.allowShare
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
    const token = await createToken(config, session, req.userData, true);
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
        const token = await createToken(config, session, user, true);
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
    const token = await createToken(config, session, user, false);
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
    res.json({ message: 'success', waiting: ctx.session.waiting.map((w) => ({ userId: w.user, name: w.name, requestedAt: w.requestedAt })) });
};

const admit = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { session } = ctx;
    const ids = req.body.all ? session.waiting.map((w) => String(w.user)) : [String(req.body.userId)];
    ids.forEach((id) => {
        if (!hasId(session.admitted, id)) session.admitted.push(id);
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
    session.waiting = session.waiting.filter((w) => String(w.user) !== id);
    if (!hasId(session.removed, id)) session.removed.push(id);
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
            .filter((p) => !sameId(p.identity, session.teacher))
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
    if (!hasId(session.removed, identity)) session.removed.push(identity);
    session.admitted = session.admitted.filter((id) => !sameId(id, identity));
    await session.save();
    await getRoomService(config).removeParticipant(session.roomName, identity).catch(() => null);
    res.json({ message: 'success' });
};

const endLive = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { config, session } = ctx;
    session.status = 'ended';
    session.endedAt = new Date();
    session.waiting = [];
    await session.save();
    await getRoomService(config).deleteRoom(session.roomName).catch(() => null);
    res.json({ message: 'success' });
};

module.exports = {
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
