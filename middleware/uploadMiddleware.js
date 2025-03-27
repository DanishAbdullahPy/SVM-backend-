// // middleware/uploadMiddleware.js
// const multer = require("multer");
// const path = require("path");

// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     cb(null, "uploads/"); // Ensure this folder exists or create it before running the server
//   },
//   filename: function (req, file, cb) {
//     cb(null, Date.now() + path.extname(file.originalname)); // Appending extension
//   },
// });

// // Filter to validate file types (e.g., only images allowed)
// const fileFilter = (req, file, cb) => {
//   const allowedTypes = /jpeg|jpg|png/;
//   const isValidType =
//     allowedTypes.test(file.mimetype.toLowerCase()) &&
//     allowedTypes.test(path.extname(file.originalname).toLowerCase());

//   if (isValidType) {
//     cb(null, true);
//   } else {
//     cb(new Error("Only JPEG, JPG, and PNG files are allowed"), false);
//   }
// };

// // Set up multer with storage and file filter
// const upload = multer({
//   storage: storage,
//   fileFilter: fileFilter,
//   limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
// });

// module.exports = upload;

const multer = require("multer");

// Setup Multer for handling image files (still required to get files from request)
const storage = multer.memoryStorage(); // Store images in memory instead of local disk

// Filter to validate file types (JPEG, JPG, PNG)
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png/;
  const isValidType =
    allowedTypes.test(file.mimetype.toLowerCase()) &&
    allowedTypes.test(file.originalname.toLowerCase());

  if (isValidType) {
    cb(null, true);
  } else {
    cb(new Error("Only JPEG, JPG, and PNG files are allowed"), false);
  }
};

// Set up multer with memory storage
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 2 * 1024 * 1024 }, // Limit file size to 2MB
});

module.exports = upload;
