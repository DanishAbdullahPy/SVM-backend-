
# SVM Backend

A robust Node.js backend for the SVM E-commerce Application, built with Express.js and Prisma ORM. This project provides a secure, scalable foundation for e-commerce functionality, including user authentication, payment processing, image uploads, and email notifications.

## Features
- **Authentication**: JWT-based authentication with password hashing using bcrypt.
- **Security**: Helmet for secure HTTP headers, rate limiting, and input validation.
- **Database**: Prisma ORM for database management with PostgreSQL.
- **File Uploads**: Image uploads to Cloudinary using Multer.
- **Payments**: Razorpay integration for payment processing.
- **Email**: Nodemailer for sending transactional emails.
- **Logging**: Winston for logging and Morgan for HTTP request logging.
- **Middleware**: CORS, cookie-parser, and express-validator for input validation.

## Prerequisites
- **Node.js**: v20.16.0 or higher
- **npm**: v10.x or higher
- **PostgreSQL**: For the database
- **Cloudinary Account**: For image storage
- **Razorpay Account**: For payment processing
- **SMTP Service**: For Nodemailer (e.g., Gmail, SendGrid)



2. **Install Dependencies**:
   npm install

3. **Set Up Environment Variables**:
   Create a `.env` file in the root directory and add the following:
   PORT=5000
   DATABASE_URL="postgresql://user:password@localhost:5432/svm_ecommerce?schema=public"
   JWT_SECRET="your_jwt_secret"
   CLOUDINARY_CLOUD_NAME="your_cloudinary_cloud_name"
   CLOUDINARY_API_KEY="your_cloudinary_api_key"
   CLOUDINARY_API_SECRET="your_cloudinary_api_secret"
   RAZORPAY_KEY_ID="your_razorpay_key_id"
   RAZORPAY_KEY_SECRET="your_razorpay_key_secret"
   NODEMAILER_EMAIL="your_email@example.com"
   NODEMAILER_PASSWORD="your_email_password"
   Adjust values based on your setup (e.g., database credentials, Cloudinary, Razorpay).

4. **Initialize the Database**:
   Run Prisma migrations to set up your database:
   npx prisma migrate dev --name init



## Scripts
- **`npm start`**: Start the server in production mode.
- **`npm run dev`**: Start the server in development mode with `nodemon`.

## Dependencies
- **@prisma/client**: Prisma ORM client for database operations.
- **bcryptjs**: Password hashing.
- **cloudinary**: Cloudinary SDK for image storage.
- **cookie-parser**: Parse cookies in requests.
- **cors**: Enable Cross-Origin Resource Sharing.
- **crypto**: Cryptographic functions.
- **dotenv**: Load environment variables from `.env`.
- **express**: Web framework for Node.js.
- **express-rate-limit**: Rate limiting middleware.
- **express-validator**: Input validation.
- **helmet**: Security headers.
- **jsonwebtoken**: JWT authentication.
- **morgan**: HTTP request logging.
- **multer**: File upload middleware.
- **multer-storage-cloudinary**: Cloudinary storage engine for Multer.
- **nodemailer**: Email sending.
- **pg**: PostgreSQL client for Node.js.
- **prisma**: Prisma CLI for database migrations.
- **razorpay**: Razorpay payment gateway integration.
- **validator**: String validation.
- **winston**: Logging library.

## Dev Dependencies
- **nodemon**: Automatically restart the server during development.

## Project Structure
```
├── node_modules/       # Dependencies
├── prisma/             # Prisma schema and migrations
├── src/                # Source code
│   ├── controllers/    # Route handlers
│   ├── helpers/        # Utility functions
│   ├── middleware/     # Custom middleware
│   ├── routes/         # API routes
│   ├── scripts/        # Scripts for automation
│   ├── services/       # Business logic
│   ├── uploads/        # Temporary file uploads
│   └── utils/          # Utility functions
├── .env                # Environment variables
├── .gitignore          # Git ignore file
├── server.js           # Entry point
├── package.json        # Project metadata and scripts
└── README.md           # This file
```






#
