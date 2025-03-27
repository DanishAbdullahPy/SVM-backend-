const prisma = require("../DB/db.config");

const getAllCategories = async (req, res) => {
  try {
    const categories = await prisma.category.findMany();
    if (categories.length === 0) {
      return res.status(404).json({ message: "No categories found" });
    }
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const addCategory = async (req, res) => {
  const { name } = req.body;
  try {
    const existingCategory = await prisma.category.findUnique({
      where: { name },
    });

    if (existingCategory) {
      return res.status(400).json({ message: "Category Already Exists" });
    }

    const category = await prisma.category.create({
      data: { name },
    });
    res.json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const deleteCategory = async (req, res) => {
  const { id } = req.params;
  try {
    const categoryExists = await prisma.category.findUnique({
      where: { id: id },
    });

    if (!categoryExists) {
      return res.status(404).json({ message: "Category does not exist" });
    }

    const category = await prisma.category.delete({
      where: { id: id },
    });
    res.json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const updateCategory = async (req, res) => {
  const { id } = req.params; // ID is a string (UUID)
  const { name } = req.body;
  try {
    const categoryExists = await prisma.category.findUnique({
      where: { id }, // Directly use the string ID without converting to integer
    });

    if (!categoryExists) {
      return res.status(404).json({ message: "Category does not exist" });
    }

    const category = await prisma.category.update({
      where: { id }, // Directly use the string ID
      data: { name },
    });
    res.json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// GET: SEARCH PRODUCTS
const searchCategory = async (req, res) => {
  const { query } = req.query;

  if (!query) {
    return res.status(400).json({ message: "Query string is required" });
  }

  try {
    const products = await prisma.category.findMany({
      where: {
        name: {
          contains: query,
          mode: "insensitive",
        },
      },
    });

    if (products.length === 0) {
      return res.status(404).json({ message: "No products found" });
    }
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: "Failed to search products." });
  }
};

module.exports = {
  addCategory,
  deleteCategory,
  updateCategory,
  getAllCategories,
  searchCategory,
};
