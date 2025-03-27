// routes/shiprocketRoutes.js

const express = require("express");
const router = express.Router();
const {
  handleCreateShiprocketOrder,
  handleTrackShipment,
  handleCancelShipment,
} = require("../controllers/shiprocketController");

// Create a Shiprocket order
router.post("/create-order", handleCreateShiprocketOrder);

// Track a Shiprocket shipment
router.get("/track/:shipmentId", handleTrackShipment);

// Cancel a Shiprocket shipment
router.post("/cancel", handleCancelShipment);

module.exports = router;
