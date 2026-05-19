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
const wrapMulter = (multerMiddleware) => (req, res, next) => {
    multerMiddleware(req, res, (err) => {
        if (err) {
            return res.status(400).json({ message: err.message || 'File upload error' });
        }
        next();
    });
};

module.exports = upload;
module.exports.wrapMulter = wrapMulter;