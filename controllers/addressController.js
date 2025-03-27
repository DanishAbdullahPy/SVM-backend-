// controllers/addressController.js
const prisma = require("../DB/db.config");

const ALLOWED_ADDRESS_TYPES = ["HOME", "OFFICE", "OTHER"];

// Add an address
const addAddress = async (req, res) => {
  // Defensive check for req.user
  if (!req.user || !req.user.id) {
    return res
      .status(401)
      .json({ message: "Unauthorized: User information missing." });
  }

  const { id: userId } = req.user; // User ID from the authentication middleware
  const { area, city, state, zipCode, type } = req.body;

  try {
    // Validate input fields
    if (!area || !city || !state || !zipCode || !type) {
      return res.status(400).json({
        message: "All fields (area, city, state, zipCode, type) are required.",
      });
    }

    // Validate address type
    if (!ALLOWED_ADDRESS_TYPES.includes(type.toUpperCase())) {
      return res.status(400).json({
        message: `Invalid address type. Allowed types are: ${ALLOWED_ADDRESS_TYPES.join(
          ", "
        )}.`,
      });
    }

    // Create a new address associated with the user
    const address = await prisma.address.create({
      data: { area, city, state, zipCode, userId, type: type.toUpperCase() },
    });

    res.status(201).json({ message: "Address added successfully.", address });
  } catch (error) {
    console.error("Error adding address:", error);
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

// Remove an address
const removeAddress = async (req, res) => {
  // Defensive check for req.user
  if (!req.user || !req.user.id) {
    return res
      .status(401)
      .json({ message: "Unauthorized: User information missing." });
  }

  const { addressId } = req.params;
  const { id: userId } = req.user; // User ID from the authentication middleware

  try {
    // Find the address to ensure it exists and belongs to the user
    const address = await prisma.address.findUnique({
      where: { id: parseInt(addressId) },
    });

    if (!address) {
      return res.status(404).json({ message: "Address not found." });
    }

    if (address.userId !== userId) {
      return res.status(403).json({
        message: "Forbidden: You are not authorized to delete this address.",
      });
    }

    // Delete the address
    await prisma.address.delete({ where: { id: parseInt(addressId) } });
    res.status(200).json({ message: "Address removed successfully." });
  } catch (error) {
    console.error("Error removing address:", error);
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

// Get all addresses for a user
const getAddresses = async (req, res) => {
  // Defensive check for req.user
  if (!req.user || !req.user.id) {
    return res
      .status(401)
      .json({ message: "Unauthorized: User information missing." });
  }

  const { id: userId } = req.user;

  try {
    // Fetch all addresses associated with the user
    const addresses = await prisma.address.findMany({
      where: { userId },
      select: {
        id: true,
        type: true,
        area: true,
        city: true,
        state: true,
        zipCode: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    res.status(200).json({ addresses });
  } catch (error) {
    console.error("Error fetching addresses:", error);
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

module.exports = {
  addAddress,
  removeAddress,
  getAddresses,
};
