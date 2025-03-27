// routes/orders.js
const express = require("express");
const router = express.Router();

const {
  createOrderRecord,
  getUserOrders,
  cancelOrder,
  getOrderDetails,
} = require("../controllers/orderController");
// const { isAuthenticated } = require("../middleware/authMiddleware");

// router.use(isAuthenticated);

// POST /api/orders => create a new order record (e.g., after Razorpay payment verification)
router.post("/", createOrderRecord);

// GET /api/orders/user/:userId => fetch all orders for a user
router.get("/user/:userId", getUserOrders);

// PATCH /api/orders/:orderId/cancel => cancel an order
router.patch("/:orderId/cancel", cancelOrder);

// GET /api/orders/:orderId => get order details by orderId (simplified route)
router.get("/:orderId", getOrderDetails);

module.exports = router;
