const express = require("express");
const {
  register,
  login,
  updateUserDetails,
  getUserWithAddresses,
  logout,
  requestResetOTP,
  resetPasswordWithOTP,
  googleAuth,
  googleAuthCallback, 
  changePassword,
} = require("../controllers/authController");
const { isAuthenticated } = require("../middleware/authMiddleware");

const router = express.Router();

// POST: Registration Route with Validation
router.post("/register", register);

// POST: Login Route with Validation
router.post("/login", login);
// GET: Google OAuth Route
router.get("/google", googleAuth); 

// GET: Google OAuth Callback Route
router.get("/google/callback", googleAuthCallback);
// UPDATE: User Details Route
router.put("/update", isAuthenticated, updateUserDetails);

// GET: User with Addresses Route
router.get("/user", isAuthenticated, getUserWithAddresses);

// POST:
router.post("/logout", logout);

// POST: Change password through current password
router.post("/change-password", isAuthenticated, changePassword);

// Request Reset OTP Route
router.post("/request-reset-otp", requestResetOTP);

// Reset Password with OTP Route
router.post("/reset-password-with-otp", resetPasswordWithOTP);
// routes/authRoutes.js

const express = require('express');
const { register, login } = require('../controllers/authController');
const { body } = require('express-validator');


// Registration Route with Validation
router.post(
  '/register',
  [
    body('name', 'Name is required').not().isEmpty(),
    body('email', 'Please include a valid email').isEmail(),
    body(
      'password',
      'Password must be at least 6 characters long'
    ).isLength({ min: 6 }),
  ],
  register
);

// Login Route with Validation
router.post(
  '/login',
  [
    body('email', 'Please include a valid email').isEmail(),
    body('password', 'Password is required').exists(),
  ],
  login
);

module.exports = router;
