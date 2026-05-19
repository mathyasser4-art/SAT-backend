const multer  = require('multer')
// func to upload photos on the uploads file
const storageEngine = multer.diskStorage({
    destination: "uploads",
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}--${file.originalname}`);
    },
});
//func to filter the extention photos thats i need 
const fileFilter = (req,file,cb) => {
    if(file.mimetype == 'image/jpeg' || file.mimetype == 'image/png' || file.mimetype == 'image/jpg' || file.mimetype == 'image/webp'){
        cb(null, true)
    }else{
        req.validationErrorImg = 'error'
        cb(null, false)
    }
}


const upload = multer({ storage: storageEngine, fileFilter: fileFilter });

// Wraps a multer middleware so that MulterErrors are caught and returned as
// JSON instead of falling through to Express's default HTML error handler.
// LIMIT_UNEXPECTED_FILE is thrown when multer encounters a non-file form field
// in a multipart/form-data request (e.g. text fields like question, chapter,
// index). These are perfectly valid — we log and ignore them so that mixed
// requests (text fields + image file) are accepted without error.
const wrapMulter = (multerMiddleware) => (req, res, next) => {
    multerMiddleware(req, res, (err) => {
        if (err) {
            if (err.code === 'LIMIT_UNEXPECTED_FILE') {
                // Text fields in a multipart form trigger this — not an error.
                console.log(`wrapMulter: ignoring LIMIT_UNEXPECTED_FILE for field "${err.field}"`);
                return next();
            }
            return res.status(400).json({ message: err.message || 'File upload error' });
        }
        next();
    });
};

module.exports = upload;
module.exports.wrapMulter = wrapMulter;