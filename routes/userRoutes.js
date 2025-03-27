const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");

// General users routes (FETCH ALL USERS)
router.get("/", userController.getAllUsers); // Fetch all products

// Get User By Id
router.get("/:id", userController.getUserById);

module.exports = router;
