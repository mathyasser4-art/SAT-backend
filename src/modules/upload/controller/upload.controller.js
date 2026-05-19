const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require('cloudinary').v2
const fs = require('fs')

cloudinaryConfig()

const uploadImage = async (req, res) => {
    try {
        if (req.validationErrorImg) {
            return res.status(400).json({ message: 'Invalid file type. Only jpg, jpeg, png, and webp images are allowed.' })
        }

        if (!req.file) {
            return res.status(400).json({ message: 'No image file provided.' })
        }

        const imageURI = req.file.path
        const { secure_url } = await cloudinary.uploader.upload(imageURI, {
            folder: 'quill-images',
            resource_type: 'image'
        })

        fs.unlinkSync(imageURI)

        return res.status(200).json({ url: secure_url })
    } catch (error) {
        return res.status(502).json({ message: error.message })
    }
}

module.exports = { uploadImage }
