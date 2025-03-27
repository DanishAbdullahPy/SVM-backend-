const express = require("express");
const router = express.Router();
const wishlistController = require("../controllers/wishlistController");

// Get wishlist for a user
router.get("/:userId", wishlistController.getWishlist);

// Add a product to the wishlist
router.post("/", wishlistController.addToWishlist);

// Remove a product from the wishlist
router.delete("/", wishlistController.removeFromWishlist);

// Clear the wishlist
router.delete("/clear", wishlistController.clearWishlist);

module.exports = router;
