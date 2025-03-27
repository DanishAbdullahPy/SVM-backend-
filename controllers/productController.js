const prisma = require("../DB/db.config");
const { isValidDate } = require("../helpers/userHelper");
const path = require("path");
const uploadOnCloudinary = require("../utils/cloudinary.js");

// GET: ALL PRODUCTS
const getAllProducts = async (req, res) => {
  try {
    // Fetch all products
    const products = await prisma.product.findMany({
      include: { category: true }, // Include related category data
      orderBy: { id: "asc" }, // Ensure consistent ordering
    });

    // Fetch total product count
    const total = await prisma.product.count();

    console.log(`Total Products: ${total}`);

    res.status(200).json({
      products,
      total,
    });
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ error: "Failed to fetch products." });
  }
};

// GET: FILTERED PRODUCTS (SHOP)
const getFilteredProducts = async (req, res) => {
  const { categoryId, minPrice, maxPrice } = req.query;

  let where = {};

  if (categoryId) {
    const categoryIds = categoryId.split(",");
    where.categoryId = { in: categoryIds };
  }

  if (minPrice || maxPrice) {
    where.price = {};
    if (minPrice) where.price.gte = parseFloat(minPrice);
    if (maxPrice) where.price.lte = parseFloat(maxPrice);
  }

  try {
    const products = await prisma.product.findMany({
      where,
      include: {
        category: true,
      },
    });

    if (products.length === 0) {
      return res.status(404).json({ message: "No products found" });
    }
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// GET: FEATURED PRODUCTS
const getFeaturedProducts = async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { featured: true, inStock: true },
      include: { category: true },
    });

    if (products.length === 0) {
      return res.status(404).json({ message: "No featured products found" });
    }
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch featured products." });
  }
};

// GET: LIMITED OFFER PRODUCTS
const getLimitedOfferProducts = async (req, res) => {
  try {
    const currentDateTime = new Date();
    const products = await prisma.product.findMany({
      where: {
        limitedOffer: true,
        discountExpiry: { gte: currentDateTime },
        inStock: true,
      },
      include: { category: true },
    });

    if (products.length === 0) {
      return res
        .status(404)
        .json({ message: "No limited offer products found" });
    }
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch limited offer products." });
  }
};

// GET: DISCOUNTED PRODUCTS
const getDiscountedProducts = async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: {
        discount: { gt: 0 },
        inStock: true,
      },
      include: { category: true },
    });

    if (products.length === 0) {
      return res.status(404).json({ message: "No discounted products found" });
    }
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch discounted products." });
  }
};

// GET: PRODUCT DETAILS USING ID WITH FAVOURITE STATUS
const getProductById = async (req, res) => {
  const { id } = req.params;
  const { userId } = req.query; // Capture userId from query params

  try {
    const product = await prisma.product.findUnique({
      where: { id },
      include: {
        category: true,
        ratings: {
          include: {
            user: true,
          },
        },
      },
    });

    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    let isFavourite = false;
    if (userId) {
      const wishlistItem = await prisma.wishlistItem.findFirst({
        where: { productId: id, wishlist: { userId: parseInt(userId, 10) } },
      });
      isFavourite = !!wishlistItem;
    }

    res.status(200).json({ ...product, favourite: isFavourite });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch product details." });
  }
};

// DELETE: DELETE PRODUCT
const deleteProduct = async (req, res) => {
  const { id } = req.params;
  try {
    const product = await prisma.product.delete({ where: { id } });
    res.status(200).json(product);
  } catch (error) {
    res.status(500).json({ error: "Failed to delete product." });
  }
};

// POST: ADD PRODUCT
// const addProduct = async (req, res) => {
//   const {
//     name,
//     price,
//     indications,
//     description,
//     inStock,
//     categoryId,
//     precautions,
//     punchline,
//     quantity,
//     dosage,
//     featured,
//     limitedOffer,
//     discount,
//     discountExpiry,
//   } = req.body;

//   const imageUrls = req.files.map(
//     (file) =>
//       `https://svm-backend-iy0e.onrender.com/uploads/${path.basename(
//         file.path
//       )}`
//   );

//   try {
//     const product = await prisma.product.create({
//       data: {
//         name,
//         price: parseFloat(price),
//         indications,
//         description,
//         inStock: inStock === "true",
//         categoryId,
//         precautions: precautions.split(","),
//         punchline,
//         quantity,
//         dosage,
//         imageUrls,
//         featured: featured === "true",
//         limitedOffer: limitedOffer === "true",
//         discount: discount ? parseFloat(discount) : 0,
//         discountExpiry: isValidDate(discountExpiry)
//           ? new Date(discountExpiry)
//           : null,
//       },
//     });
//     res.status(201).json(product);
//   } catch (error) {
//     console.error("Error adding product:", error);
//     res
//       .status(500)
//       .json({ error: "Failed to add product.", details: error.message });
//   }
// };

const addProduct = async (req, res) => {
  const {
    name,
    price,
    indications,
    description,
    inStock,
    categoryId,
    precautions,
    punchline,
    quantity,
    dosage,
    featured,
    limitedOffer,
    discount,
    discountExpiry,
  } = req.body;

  const imageUrls = [];

  try {
    // Upload each file to Cloudinary
    for (const file of req.files) {
      const uploadedImage = await uploadOnCloudinary(file.buffer); // Pass the file buffer to Cloudinary
      if (uploadedImage) {
        imageUrls.push(uploadedImage.url); // Store Cloudinary URL
      }
    }

    const product = await prisma.product.create({
      data: {
        name,
        price: parseFloat(price),
        indications,
        description,
        inStock: inStock === "true",
        categoryId,
        precautions: precautions.split(","),
        punchline,
        quantity,
        dosage,
        imageUrls, // Save image URLs from Cloudinary
        featured: featured === "true",
        limitedOffer: limitedOffer === "true",
        discount: discount ? parseFloat(discount) : 0,
        discountExpiry: isValidDate(discountExpiry)
          ? new Date(discountExpiry)
          : null,
      },
    });

    res.status(201).json(product);
  } catch (error) {
    console.error("Error adding product:", error);
    res
      .status(500)
      .json({ error: "Failed to add product.", details: error.message });
  }
};

// PUT: UPDATE PRODUCT
// const updateProduct = async (req, res) => {
//   const { id } = req.params;
//   const {
//     name,
//     price,
//     indications,
//     description,
//     inStock,
//     categoryId,
//     precautions,
//     punchline,
//     quantity,
//     dosage,
//     featured,
//     limitedOffer,
//     discount,
//     discountExpiry,
//   } = req.body;

//   const imageUrls =
//     req.files?.map(
//       (file) =>
//         `https://svm-backend-iy0e.onrender.com/uploads/${path.basename(
//           file.path
//         )}`
//     ) || [];

//   try {
//     const product = await prisma.product.update({
//       where: { id },
//       data: {
//         name,
//         price: parseFloat(price),
//         indications,
//         description,
//         inStock: inStock === "true",
//         categoryId,
//         precautions: precautions.split(","),
//         punchline,
//         quantity,
//         dosage,
//         imageUrls: imageUrls.length > 0 ? { push: imageUrls } : undefined,
//         featured: featured === "true",
//         limitedOffer: limitedOffer === "true",
//         discount: discount ? parseFloat(discount) : 0,
//         discountExpiry: isValidDate(discountExpiry)
//           ? new Date(discountExpiry)
//           : null,
//       },
//     });

//     res.status(200).json(product);
//   } catch (error) {
//     res.status(500).json({ error: "Failed to update product." });
//   }
// };
const updateProduct = async (req, res) => {
  const { id } = req.params;
  const {
    name,
    price,
    indications,
    description,
    inStock,
    categoryId,
    precautions,
    punchline,
    quantity,
    dosage,
    featured,
    limitedOffer,
    discount,
    discountExpiry,
  } = req.body;

  const imageUrls = [];

  try {
    // Upload files to Cloudinary
    for (const file of req.files) {
      const uploadedImage = await uploadOnCloudinary(file.buffer); // Use buffer for Cloudinary upload
      if (uploadedImage) {
        imageUrls.push(uploadedImage.url); // Store Cloudinary URL
      }
    }

    const product = await prisma.product.update({
      where: { id },
      data: {
        name,
        price: parseFloat(price),
        indications,
        description,
        inStock: inStock === "true",
        categoryId,
        precautions: precautions.split(","),
        punchline,
        quantity,
        dosage,
        imageUrls: imageUrls.length > 0 ? { push: imageUrls } : undefined, // Append new images if any
        featured: featured === "true",
        limitedOffer: limitedOffer === "true",
        discount: discount ? parseFloat(discount) : 0,
        discountExpiry: isValidDate(discountExpiry)
          ? new Date(discountExpiry)
          : null,
      },
    });

    res.status(200).json(product);
  } catch (error) {
    res.status(500).json({ error: "Failed to update product." });
  }
};

// GET: PRODUCTS BY CATEGORY ID
// const getProductsByCategory = async (req, res) => {
//   const { categoryId } = req.params; // get the category ID from the URL parameter

//   try {
//     const products = await prisma.product.findMany({
//       where: { categoryId: categoryId },
//       include: { category: true }, // Optionally include category details if needed
//     });

//     if (products.length === 0) {
//       return res
//         .status(404)
//         .json({ message: "No products found for this category" });
//     }

//     res.status(200).json(products);
//   } catch (error) {
//     res
//       .status(500)
//       .json({ error: "Failed to fetch products for the category." });
//   }
// };

// GET: PRODUCTS BY CATEGORY
const getProductsByCategory = async (req, res) => {
  const { categoryId } = req.params; // Extract categoryId from URL parameters

  // Validate categoryId
  if (!categoryId) {
    return res.status(400).json({ message: "Category ID is required." });
  }

  try {
    // Fetch products that belong to the specified category
    const products = await prisma.product.findMany({
      where: { categoryId: categoryId },
      include: { category: true }, // Include category details if needed
      orderBy: { id: "asc" }, // Optional: Order products by ID
    });

    // If no products are found, return a 404 response
    if (products.length === 0) {
      return res
        .status(404)
        .json({ message: "No products found for this category." });
    }

    // Respond with the fetched products
    res.status(200).json(products);
  } catch (error) {
    console.error("Error fetching products by category:", error);
    res
      .status(500)
      .json({ error: "Failed to fetch products for the category." });
  }
};

module.exports = {
  getAllProducts,
  getFilteredProducts,
  getFeaturedProducts,
  getLimitedOfferProducts,
  getDiscountedProducts,
  getProductById,
  getProductsByCategory,
  addProduct,
  deleteProduct,
  updateProduct,
};
