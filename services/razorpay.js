const Razorpay = require("razorpay");

// Check for required environment variables
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.error(
    "Error: RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET must be set in the environment variables."
  );
  process.exit(1); // Exit the process to prevent undefined behavior
}

// Initialize Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

module.exports = razorpay;
