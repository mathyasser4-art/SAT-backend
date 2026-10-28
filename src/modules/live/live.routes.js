const liveRouter = require('express').Router()
const live = require('./live.controller')
const { userAuth, teacherAuth } = require('../../middleware/auth')

// LiveClass (per-course video meetings). Host-only actions check course ownership in the controller.
liveRouter.get('/live/active', userAuth, live.getActive)
liveRouter.get('/live/:courseId/info', userAuth, live.getInfo)
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

module.exports = liveRouter
