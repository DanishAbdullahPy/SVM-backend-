const prisma = require("../DB/db.config");

// Add a new rating
const addRating = async (req, res) => {
  const { productId, userId, rating, feedback } = req.body;

  if (!productId || !userId || !rating) {
    return res.status(400).json({
      error: "Missing required fields",
    });
  }
  try {
    const newRating = await prisma.rating.create({
      data: {
        productId,
        userId,
        rating,
        feedback,
      },
    });
    res.status(201).json(newRating);
  } catch (error) {
    console.error("Error adding rating:", error);
    res.status(500).json({ error: "Failed to add rating." });
  }
};

// Get all ratings for a product
const getProductRatings = async (req, res) => {
  const { productId } = req.params;

  try {
    const ratings = await prisma.rating.findMany({
      where: { productId },
      include: {
        user: { select: { name: true } }, // Include user name
      },
    });
    res.status(200).json(ratings);
  } catch (error) {
    console.error("Error fetching product ratings:", error);
    res.status(500).json({ error: "Failed to fetch product ratings." });
  }
};

// Update a rating
const updateRating = async (req, res) => {
  const { id } = req.params;
  const { rating, feedback } = req.body;

  try {
    const updatedRating = await prisma.rating.update({
      where: { id: parseInt(id, 10) },
      data: { rating, feedback },
    });
    res.status(200).json(updatedRating);
  } catch (error) {
    console.error("Error updating rating:", error);
    res.status(500).json({ error: "Failed to update rating." });
  }
};

// Delete a rating
const deleteRating = async (req, res) => {
  const { id } = req.params;

  try {
    await prisma.rating.delete({
      where: { id: parseInt(id, 10) },
    });
    res.status(200).json({ message: "Rating deleted successfully." });
  } catch (error) {
    console.error("Error deleting rating:", error);
    res.status(500).json({ error: "Failed to delete rating." });
  }
};

module.exports = {
  addRating,
  getProductRatings,
  updateRating,
  deleteRating,
};
