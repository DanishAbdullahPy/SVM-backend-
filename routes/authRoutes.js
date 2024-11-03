// routes/authRoutes.js

const express = require('express');
const { register, login } = require('../controllers/authController');
const { body } = require('express-validator');

const router = express.Router();

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
