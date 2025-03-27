const express = require("express");
const router = express.Router();
const ratingController = require("../controllers/ratingController");

// Add a new rating
router.post("/", ratingController.addRating);

// Get all ratings for a product
router.get("/:productId", ratingController.getProductRatings);

// Update a rating
router.put("/:id", ratingController.updateRating);

// Delete a rating
router.delete("/:id", ratingController.deleteRating);

module.exports = router;
