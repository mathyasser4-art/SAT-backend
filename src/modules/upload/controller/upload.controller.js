const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require('cloudinary').v2
const fs = require('fs')

cloudinaryConfig()

const uploadImage = async (req, res) => {
    console.log('[upload] POST /api/upload-image received')
    console.log('[upload] content-type:', req.headers['content-type'])
    console.log('[upload] req.file:', req.file)
    console.log('[upload] req.validationErrorImg:', req.validationErrorImg)

    try {
        if (req.validationErrorImg) {
            console.log('[upload] Rejecting: invalid file type')
            return res.status(400).json({ message: 'Invalid file type. Only jpg, jpeg, png, and webp images are allowed.' })
        }

        if (!req.file) {
            console.log('[upload] Rejecting: no file present on req.file')
            return res.status(400).json({ message: 'No image file provided.' })
        }

        const imageURI = req.file.path
        console.log('[upload] File saved to disk at:', imageURI)
        console.log('[upload] File details — originalname:', req.file.originalname, '| mimetype:', req.file.mimetype, '| size:', req.file.size)

        console.log('[upload] Starting Cloudinary upload...')
        const result = await cloudinary.uploader.upload(imageURI, {
            folder: 'quill-images',
            resource_type: 'image'
        })
        console.log('[upload] Cloudinary upload complete — public_id:', result.public_id, '| secure_url:', result.secure_url)

        try {
            fs.unlinkSync(imageURI)
            console.log('[upload] Temp file deleted:', imageURI)
        } catch (unlinkErr) {
            console.warn('[upload] Failed to delete temp file:', imageURI, unlinkErr.message)
        }

        console.log('[upload] Sending 200 response with url:', result.secure_url)
        return res.status(200).json({ url: result.secure_url })
    } catch (error) {
        console.error('[upload] ERROR during upload process:', error.message)
        console.error('[upload] Stack trace:', error.stack)
        if (!res.headersSent) {
            return res.status(500).json({ message: error.message })
        }
    }
}

module.exports = { uploadImage }
