// routes/addressRoutes.js
const express = require("express");
const { isAuthenticated } = require("../middleware/authMiddleware");
const {
  addAddress,
  removeAddress,
  getAddresses,
} = require("../controllers/addressController");

const router = express.Router();

// Apply 'isAuthenticated' middleware to all routes in this router
router.use(isAuthenticated);

// Add a new address
router.post("/", addAddress);

// Remove an address
router.delete("/:addressId", removeAddress);

// Get all addresses for a user
router.get("/", getAddresses);

module.exports = router;
