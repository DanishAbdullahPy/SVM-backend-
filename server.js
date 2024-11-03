// server.js

const express = require('express');
const dotenv = require('dotenv');
const morgan = require('morgan'); // HTTP request logger
const authRoutes = require('./routes/authRoutes');
const { errorHandler } = require('./middleware/errorMiddleware');

dotenv.config(); // Initialize dotenv first

const app = express();
const PORT = process.env.PORT || 5000;

// HTTP request logger
app.use(morgan('dev'));

// Middleware to parse JSON
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Root Endpoint
app.get('/', (req, res) => {
  res.send('Welcome to the E-commerce Auth API');
});

// Error Handling Middleware
app.use(errorHandler);

// Start the Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
