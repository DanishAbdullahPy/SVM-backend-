// const prisma = require("../DB/db.config");
const prisma = require("../DB/db.config");
// Add product to cart
const addToCart = async (req, res) => {
  const { userId, productId, quantity } = req.body;

  try {
    // Input validation
    if (!userId || !productId || !quantity || quantity <= 0) {
      console.error("Invalid Input:", { userId, productId, quantity });
      return res.status(400).json({
        error: "Invalid input. Ensure all fields are correct.",
      });
    }

    const userIdInt = parseInt(userId);

    // Check if user exists
    const userExists = await prisma.user.findUnique({
      where: { id: userIdInt },
    });
    if (!userExists) {
      console.error("User does not exist:", { userId });
      return res.status(400).json({ error: "User not found." });
    }

    // Check if product exists
    const productExists = await prisma.product.findUnique({
      where: { id: productId },
    });
    if (!productExists) {
      console.error("Product does not exist:", { productId });
      return res.status(400).json({ error: "Product not found." });
    }

    // Fetch or create cart
    let cart = await prisma.cart.findUnique({
      where: { userId: userIdInt },
      include: { items: true },
    });

    if (!cart) {
      cart = await prisma.cart.create({ data: { userId: userIdInt } });
    }

    // Check if item already exists in cart
    const existingItem = await prisma.cartItem.findFirst({
      where: { cartId: cart.id, productId },
    });

    if (existingItem) {
      await prisma.cartItem.update({
        where: { id: existingItem.id },
        data: { quantity: existingItem.quantity + quantity },
      });
    } else {
      await prisma.cartItem.create({
        data: { cartId: cart.id, productId, quantity },
      });
    }

    res.status(200).json({ message: "Product added to cart successfully." });
  } catch (error) {
    console.error("Error in addToCart:", error);
    res.status(500).json({ error: "Failed to add product to cart." });
  }
};

// Get user cart
const getUserCart = async (req, res) => {
  const { userId } = req.params;

  try {
    const userIdInt = parseInt(userId, 10);

    // Fetch the cart using the unique userId
    const cart = await prisma.cart.findUnique({
      where: { userId: userIdInt },
      include: {
        items: {
          include: { product: true }, // Include product details for each cart item
        },
      },
    });

    if (!cart || !cart.items.length) {
      return res.status(200).json({ message: "Cart is empty.", items: [] });
    }

    res.status(200).json(cart);
  } catch (error) {
    console.error("Error fetching cart:", error);
    res.status(500).json({ error: "Failed to fetch cart." });
  }
};

// Update cart item quantity
const updateCartItem = async (req, res) => {
  const { cartItemId, quantity } = req.body;

  try {
    if (quantity <= 0) {
      return res
        .status(400)
        .json({ error: "Quantity must be greater than 0." });
    }

    await prisma.cartItem.update({
      where: { id: cartItemId },
      data: { quantity },
    });

    res.status(200).json({ message: "Cart item updated successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to update cart item." });
  }
};

// Remove product from cart
const removeFromCart = async (req, res) => {
  const { cartItemId } = req.body;

  try {
    await prisma.cartItem.delete({
      where: { id: cartItemId },
    });

    res
      .status(200)
      .json({ message: "Product removed from cart successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to remove product from cart." });
  }
};

// clear cart
const clearCart = async (req, res) => {
  const { userId } = req.body;

  try {
    if (!userId) {
      return res.status(400).json({ error: "User ID is required." });
    }

    const userIdInt = parseInt(userId, 10);

    // Check if cart exists
    const cart = await prisma.cart.findUnique({
      where: { userId: userIdInt },
      include: { items: true },
    });

    if (!cart) {
      return res.status(200).json({ message: "Cart is already empty." });
    }

    // Delete all cart items
    await prisma.cartItem.deleteMany({
      where: { cartId: cart.id },
    });

    res.status(200).json({ message: "Cart cleared successfully." });
  } catch (error) {
    console.error("Error in clearCart:", error);
    res.status(500).json({ error: "Failed to clear the cart." });
  }
};

module.exports = {
  addToCart,
  getUserCart,
  updateCartItem,
  removeFromCart,
  clearCart,
};
