const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require('cloudinary').v2
const fs = require('fs')

cloudinaryConfig()

// Safely serialise any thrown value — Error instances, plain objects, strings, etc.
const serializeError = (err) => {
    if (err === null || err === undefined) return String(err)
    if (typeof err === 'string') return err
    if (err instanceof Error) {
        return JSON.stringify({ message: err.message, stack: err.stack, ...err }, null, 2)
    }
    try {
        return JSON.stringify(err, null, 2)
    } catch {
        return String(err)
    }
}

// Extract the most useful human-readable message from any thrown value.
const extractMessage = (err) => {
    if (err === null || err === undefined) return 'Unknown error (null/undefined thrown)'
    if (typeof err === 'string') return err
    if (typeof err === 'object') {
        // Cloudinary API errors surface as { error: { message } } or { message }
        if (err.error && typeof err.error.message === 'string') return err.error.message
        if (typeof err.message === 'string' && err.message) return err.message
        if (err.http_code) return `Cloudinary HTTP ${err.http_code}`
    }
    return 'Unexpected error during upload'
}

const uploadImage = async (req, res) => {
    console.log('[upload] POST /api/upload-image received')
    console.log('[upload] content-type:', req.headers['content-type'])
    console.log('[upload] req.file:', req.file)
    console.log('[upload] req.validationErrorImg:', req.validationErrorImg)

    // Verify Cloudinary credentials are present before attempting an upload.
    const { CLOUDNAME, CLOUDAPIKEY, CLOUDAPISECRET } = process.env
    if (!CLOUDNAME || !CLOUDAPIKEY || !CLOUDAPISECRET) {
        console.error('[upload] Cloudinary credentials missing — CLOUDNAME:', CLOUDNAME ? 'set' : 'MISSING', '| CLOUDAPIKEY:', CLOUDAPIKEY ? 'set' : 'MISSING', '| CLOUDAPISECRET:', CLOUDAPISECRET ? 'set' : 'MISSING')
        return res.status(500).json({ message: 'Server misconfiguration: Cloudinary credentials are not set.' })
    }

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
        const message = extractMessage(error)
        console.error('[upload] ERROR during upload process — type:', typeof error, '| constructor:', error && error.constructor && error.constructor.name)
        console.error('[upload] Full error:', serializeError(error))
        console.error('[upload] Extracted message:', message)
        if (!res.headersSent) {
            return res.status(500).json({ message })
        }
    }
}

module.exports = { uploadImage }
