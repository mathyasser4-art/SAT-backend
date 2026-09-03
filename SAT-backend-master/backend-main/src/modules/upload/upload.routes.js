const uploadRouter = require('express').Router()
const { uploadImage } = require('./controller/upload.controller')
const upload = require('../../middleware/handleMulter')
const { wrapMulter } = require('../../middleware/handleMulter')

uploadRouter.post('/api/upload-image', wrapMulter(upload.single('file')), uploadImage)

module.exports = uploadRouter
