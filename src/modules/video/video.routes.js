const videoRouter = require('express').Router()
const { getVideos, saveVideos } = require('./controller/video.controller')
const { teacherAuth } = require('../../middleware/auth')

videoRouter.get('/videos/:scope', getVideos)
videoRouter.put('/videos/:scope', teacherAuth, saveVideos)

module.exports = videoRouter
