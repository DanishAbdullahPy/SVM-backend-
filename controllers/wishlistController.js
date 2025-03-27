const prisma = require("../DB/db.config");

// Get wishlist for a user
const getWishlist = async (req, res) => {
  try {
    const { userId } = req.params; // Extract user ID from request parameters

    const wishlist = await prisma.wishlist.findUnique({
      where: { userId: parseInt(userId, 10) },
      include: {
        items: {
          include: {
            product: true, // Include product details for each wishlist item
          },
        },
      },
    });

    if (!wishlist) {
      return res
        .status(404)
        .json({ message: "Wishlist not found for the user." });
    }

    res.status(200).json(wishlist);
  } catch (error) {
    console.error("Error fetching wishlist:", error);
    res.status(500).json({ error: "Failed to fetch wishlist." });
  }
};

// Add a product to the wishlist
const addToWishlist = async (req, res) => {
  try {
    const { userId, productId } = req.body;

    // Find the user's wishlist
    let wishlist = await prisma.wishlist.findUnique({
      where: { userId: parseInt(userId, 10) },
    });

    // Create a wishlist for the user if it doesn't exist
    if (!wishlist) {
      wishlist = await prisma.wishlist.create({
        data: {
          user: {
            connect: { id: parseInt(userId, 10) },
          },
        },
      });
    }

    // Check if the product is already in the wishlist
    const existingItem = await prisma.wishlistItem.findFirst({
      where: {
        wishlistId: wishlist.id,
        productId,
      },
    });

    if (existingItem) {
      return res.status(400).json({ message: "Product already in wishlist." });
    }

    // Add the product to the wishlist
    const newItem = await prisma.wishlistItem.create({
      data: {
        wishlistId: wishlist.id,
        productId,
      },
    });

    res.status(201).json(newItem);
  } catch (error) {
    console.error("Error adding to wishlist:", error);
    res.status(500).json({ error: "Failed to add product to wishlist." });
  }
};

// Remove a product from the wishlist
const removeFromWishlist = async (req, res) => {
  try {
    const { userId, productId } = req.body;

    // Find the user's wishlist
    const wishlist = await prisma.wishlist.findUnique({
      where: { userId: parseInt(userId, 10) },
    });

    if (!wishlist) {
      return res
        .status(404)
        .json({ message: "Wishlist not found for the user." });
    }

    // Remove the product from the wishlist
    await prisma.wishlistItem.deleteMany({
      where: {
        wishlistId: wishlist.id,
        productId,
      },
    });

    res.status(200).json({ message: "Product removed from wishlist." });
  } catch (error) {
    console.error("Error removing product from wishlist:", error);
    res.status(500).json({ error: "Failed to remove product from wishlist." });
  }
};

// Clear the wishlist
const clearWishlist = async (req, res) => {
  try {
    const { userId } = req.body;

    // Find the user's wishlist
    const wishlist = await prisma.wishlist.findUnique({
      where: { userId: parseInt(userId, 10) },
    });

    if (!wishlist) {
      return res
        .status(404)
        .json({ message: "Wishlist not found for the user." });
    }

    // Delete all items in the wishlist
    await prisma.wishlistItem.deleteMany({
      where: { wishlistId: wishlist.id },
    });

    res.status(200).json({ message: "Wishlist cleared." });
  } catch (error) {
    console.error("Error clearing wishlist:", error);
    res.status(500).json({ error: "Failed to clear wishlist." });
  }
};

module.exports = {
  getWishlist,
  addToWishlist,
  removeFromWishlist,
  clearWishlist,
};
