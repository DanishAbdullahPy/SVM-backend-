const prisma = require("../DB/db.config");

const getAllUsers = async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        name: true,
      },
    });
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

const getUserById = async (req, res) => {
  const { id } = req.params;

  // Validate and parse the 'id' to an integer
  const userId = parseInt(id, 10);

  if (isNaN(userId)) {
    return res
      .status(400)
      .json({ error: "Invalid user ID. ID must be an integer." });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
        role: true,
        ratings: true,
        wishlist: true,
        mobile: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = {
  getAllUsers,
  getUserById,
};
