const crypto = require('crypto');
const liveRecordingModel = require('../../../DB/models/liveRecording.model');
const { getConfig, loadCourseRole, loadHostSession, pushRoomMetadata } = require('./live.controller');
const recording = require('./recording.service');

// ---- Cloud recording ----------------------------------------------------------------------------
// The host records the meeting to the cloud (LiveKit Egress -> S3/R2). Everyone in the room sees a
// "Recording" sign (room metadata); the finished MP4s are listed for the course's teacher and students.

const PENDING = ['recording', 'processing'];

const recordingTitle = (course, date) => `${course.name} — ${date.toISOString().slice(0, 10)}`;

const fileName = (rec) => `${(rec.title || 'LiveClass').replace(/[^\p{L}\p{N} _-]+/gu, '-').replace(/\s+/g, ' ').replace(/-{2,}/g, '-').trim() || 'LiveClass'}.mp4`;

// LiveKit (in the cloud) opens the recorder page on the site the host started from, so it must be a
// public https site of ours; RECORDING_PAGE_ORIGIN overrides it. Otherwise LiveKit's plain layout is used.
const RECORDER_SITES = /(^|\.)(satarea\.tech|mrshahin\.com)$/;
const recorderPageUrl = (req) => {
    const fixed = (process.env.RECORDING_PAGE_ORIGIN || '').trim().replace(/\/+$/, '');
    let origin;
    try {
        origin = new URL(fixed || req.headers.origin || '');
    } catch (e) {
        return '';
    }
    if (!fixed && (origin.protocol !== 'https:' || !RECORDER_SITES.test(origin.hostname))) return '';
    return `${origin.origin}/live/recorder${req.body && req.body.lang === 'ar' ? '?lang=ar' : ''}`;
};

const recordingInfo = (rec, storage) => ({
    id: rec._id,
    title: rec.title,
    status: rec.status,
    startedAt: rec.startedAt,
    endedAt: rec.endedAt,
    duration: rec.duration,
    size: rec.size,
    url: rec.status === 'ready' && storage ? recording.playUrl(storage, rec.fileKey) : undefined,
    downloadUrl: rec.status === 'ready' && storage ? recording.downloadUrl(storage, rec.fileKey, fileName(rec)) : undefined
});

// Recordings finish uploading after they are stopped, so pending ones are checked against LiveKit
// whenever they are listed (no webhook setup needed).
const refreshRecording = async (config, rec) => {
    if (!config || !PENDING.includes(rec.status)) return rec;
    let info = null;
    try {
        info = await recording.getEgressInfo(config, rec.egressId);
    } catch (e) {
        return rec;
    }
    if (!info) return rec;
    const outcome = recording.egressOutcome(info);
    if (outcome.status === rec.status) return rec;
    Object.assign(rec, outcome);
    if (outcome.status !== 'recording' && !rec.endedAt) rec.endedAt = new Date();
    await rec.save();
    return rec;
};

const startRecording = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { config, session, course } = ctx;
    const storage = recording.getRecordingConfig();
    if (!storage) return res.status(503).json({ message: 'Cloud recording is not set up on this server', status: 'recording_off' });
    if (session.recordingEgress) {
        return res.json({ message: 'success', recording: { startedAt: session.recordingStartedAt } });
    }

    const now = new Date();
    const fileKey = `liveclass/${course._id}/${now.toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(4).toString('hex')}.mp4`;
    let info;
    try {
        info = await recording.startRoomRecording(config, storage, session.roomName, fileKey, recorderPageUrl(req));
    } catch (e) {
        console.error('LiveClass recording failed to start:', e.message);
        return res.status(502).json({ message: 'Could not start the recording', status: 'recording_failed' });
    }
    await liveRecordingModel.create({
        course: course._id,
        session: session._id,
        teacher: req.userData._id,
        egressId: info.egressId,
        title: recordingTitle(course, now),
        fileKey,
        startedAt: now
    });
    session.recordingEgress = info.egressId;
    session.recordingStartedAt = now;
    await session.save();
    await pushRoomMetadata(config, session);
    res.json({ message: 'success', recording: { startedAt: now } });
};

const stopRecording = async (req, res) => {
    const ctx = await loadHostSession(req, res);
    if (!ctx) return;
    const { config, session } = ctx;
    const egressId = session.recordingEgress;
    if (!egressId) return res.json({ message: 'success' });
    // It may already have ended on LiveKit's side (failed, limit reached); the record is refreshed later.
    await recording.stopRoomRecording(config, egressId).catch(() => null);
    const rec = await liveRecordingModel.findOne({ egressId });
    if (rec && rec.status === 'recording') {
        rec.status = 'processing';
        rec.endedAt = new Date();
        await rec.save();
    }
    session.recordingEgress = '';
    session.recordingStartedAt = undefined;
    await session.save();
    await pushRoomMetadata(config, session);
    res.json({ message: 'success' });
};

// Teachers see every recording of the course (also ones still processing or failed); students see
// the ready ones.
const listRecordings = async (req, res) => {
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    const config = getConfig();
    const storage = recording.getRecordingConfig();
    const isHost = ctx.role === 'host';
    const query = { course: ctx.course._id };
    if (!isHost) query.status = { $in: ['ready', ...PENDING] };
    const records = await liveRecordingModel.find(query).sort({ startedAt: -1 }).limit(100);
    const fresh = await Promise.all(records.map((rec) => refreshRecording(config, rec)));
    const visible = isHost ? fresh : fresh.filter((rec) => rec.status === 'ready');
    res.json({
        message: 'success',
        enabled: !!(config && storage),
        recordings: visible.map((rec) => recordingInfo(rec, storage))
    });
};

const deleteRecording = async (req, res) => {
    const ctx = await loadCourseRole(req, res);
    if (!ctx) return;
    if (ctx.role !== 'host') return res.status(403).json({ message: 'Only the course teacher can delete recordings' });
    const { recordingId } = req.params;
    if (!/^[0-9a-fA-F]{24}$/.test(recordingId)) return res.status(400).json({ message: 'Invalid recording id' });
    const rec = await liveRecordingModel.findOne({ _id: recordingId, course: ctx.course._id });
    if (!rec) return res.status(404).json({ message: 'Recording not found' });
    await refreshRecording(getConfig(), rec);
    if (PENDING.includes(rec.status)) {
        return res.status(409).json({ message: 'This recording is still being saved, try again in a few minutes' });
    }
    const storage = recording.getRecordingConfig();
    if (storage && rec.status === 'ready') {
        try {
            await recording.deleteObject(storage, rec.fileKey);
        } catch (e) {
            console.error('LiveClass recording delete failed:', e.message);
            return res.status(502).json({ message: 'Could not delete the file from storage' });
        }
    }
    await liveRecordingModel.deleteOne({ _id: rec._id });
    res.json({ message: 'success' });
};

module.exports = {
    startRecording,
    stopRecording,
    listRecordings,
    deleteRecording
};
