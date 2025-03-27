const cloudinary = require("cloudinary").v2;
require("dotenv").config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async (fileBuffer, filename) => {
  try {
    if (!fileBuffer) return null;

    return new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: "auto",
          public_id: filename, // Optional
          // ❌ Remove "upload_preset" if you're using signed uploads
        },
        (error, result) => {
          if (error) {
            console.error("Error uploading to Cloudinary:", error);
            return reject(error);
          }
          console.log("File is uploaded on Cloudinary", result.url);
          resolve(result);
        }
      );

      uploadStream.end(fileBuffer);
    });
  } catch (error) {
    console.error("Error uploading to Cloudinary:", error);
    return null;
  }
};

module.exports = uploadOnCloudinary;
