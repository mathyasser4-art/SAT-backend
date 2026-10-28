const liveRouter = require('express').Router()
const rateLimit = require('express-rate-limit')
const live = require('./live.controller')
const recording = require('./live.recording.controller')
const { userAuth, teacherAuth } = require('../../middleware/auth')

// Guest endpoints are public, so they get their own limits on top of the global one: a waiting
// guest polls every few seconds, and asking in as a NEW guest is limited much more tightly.
const guestLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many requests, please try again in a minute' }
})
const newGuestLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => !!(req.body && req.body.guestId),
    message: { message: 'Too many join attempts, please try again later' }
})

// Guests (no account) joining through a course's invite link. Declared first so "guest" is never
// read as a course id.
liveRouter.get('/live/guest/:token', guestLimiter, live.guestInfo)
liveRouter.post('/live/guest/:token/join', guestLimiter, newGuestLimiter, live.guestJoin)
liveRouter.post('/live/guest/:token/leave', guestLimiter, live.guestLeave)

// LiveClass (per-course video meetings). Host-only actions check course ownership in the controller.
liveRouter.get('/live/active', userAuth, live.getActive)
liveRouter.get('/live/:courseId/info', userAuth, live.getInfo)
liveRouter.get('/live/:courseId/guest-link', userAuth, live.getGuestLink)
liveRouter.put('/live/:courseId/guest-link', userAuth, live.updateGuestLink)
liveRouter.post('/live/:courseId/start', teacherAuth, live.startLive)
liveRouter.post('/live/:courseId/join', userAuth, live.joinLive)
liveRouter.post('/live/:courseId/leave-waiting', userAuth, live.leaveWaiting)
liveRouter.get('/live/:courseId/waiting', userAuth, live.getWaiting)
liveRouter.post('/live/:courseId/admit', userAuth, live.admit)
liveRouter.post('/live/:courseId/deny', userAuth, live.denyWaiting)
liveRouter.put('/live/:courseId/settings', userAuth, live.updateSettings)
liveRouter.post('/live/:courseId/mute', userAuth, live.muteParticipant)
liveRouter.post('/live/:courseId/mute-all', userAuth, live.muteAll)
liveRouter.post('/live/:courseId/remove', userAuth, live.removeParticipant)
liveRouter.post('/live/:courseId/end', userAuth, live.endLive)
liveRouter.post('/live/:courseId/recording/start', userAuth, recording.startRecording)
liveRouter.post('/live/:courseId/recording/stop', userAuth, recording.stopRecording)
liveRouter.get('/live/:courseId/recordings', userAuth, recording.listRecordings)
liveRouter.delete('/live/:courseId/recordings/:recordingId', userAuth, recording.deleteRecording)

module.exports = liveRouter
