// controllers/authController.js

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const { findUserByEmail, createUser } = require('../models/userModel');

// Registration Controller
const register = async (req, res) => {
  // Handle validation results
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(`Validation errors: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }
  
  let { name, email, password } = req.body;

  // Normalize email to lowercase
  email = email.toLowerCase();

  try {
    // Check if user already exists
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      console.warn(`Registration attempt with existing email: ${email}`);
      return res.status(400).json({ message: 'User already exists.' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = await createUser(name, email, hashedPassword);

    // Generate JWT
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({
      message: 'User registered successfully.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

// Login Controller
const login = async (req, res) => {
  // Handle validation results
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(`Validation errors: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  let { email, password } = req.body;

  // Normalize email to lowercase
  email = email.toLowerCase();

  try {
    // Find user by email
    const user = await findUserByEmail(email);
    if (!user) {
      console.warn(`Login attempt with unregistered email: ${email}`);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.warn(`Invalid password attempt for email: ${email}`);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    // Respond with token and user info
    res.status(200).json({
      message: 'Logged in successfully.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

module.exports = {
  register,
  login,
};
