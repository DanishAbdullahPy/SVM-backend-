const prisma = require("../DB/db.config");

const createOrderRecord = async (req, res) => {
  try {
    const {
      razorpay_order_id, // The Razorpay order ID
      userId, // ID of the user placing the order
      cartItems, // Array of items: [{ productId, quantity, price }, ...]
      amount, // Total amount (in smallest currency unit if you prefer)
      currency, // e.g. "INR"
      receipt, // e.g. "receipt_123"
    } = req.body;

    // Create the order in the DB
    // We set status = "PAID" here, assuming you're calling this AFTER successful payment verification.
    const newOrder = await prisma.order.create({
      data: {
        orderId: razorpay_order_id,
        userId: userId,
        receipt: receipt,
        amount: amount,
        currency: currency,
        status: "PAID",
        items: {
          create: cartItems.map((item) => ({
            productId: item.productId,
            quantity: item.quantity,
            price: item.price,
          })),
        },
      },
      include: { items: true }, // so we can see order items in the response
    });

    return res.status(201).json({ success: true, order: newOrder });
  } catch (error) {
    console.error("Error creating order record:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to create order",
    });
  }
};

/**
 * Get all orders for a specific user
 */
const getUserOrders = async (req, res) => {
  try {
    const { userId } = req.params;
    const { filter } = req.query; // 'month', 'week', 'year'

    let startDate, endDate;

    const now = new Date();
    if (filter === "month") {
      startDate = new Date(now.getFullYear(), now.getMonth(), 1);
      endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    } else if (filter === "week") {
      const firstDayOfWeek = now.getDate() - now.getDay(); // Sunday
      startDate = new Date(now.setDate(firstDayOfWeek));
      endDate = new Date(now.setDate(firstDayOfWeek + 6));
    } else if (filter === "year") {
      startDate = new Date(now.getFullYear(), 0, 1);
      endDate = new Date(now.getFullYear(), 11, 31);
    }

    const whereCondition = {
      userId: Number(userId),
      ...(filter && {
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      }),
    };

    const orders = await prisma.order.findMany({
      where: whereCondition,
      include: {
        items: {
          include: {
            product: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    return res.json({ success: true, orders });
  } catch (error) {
    console.error("Error fetching user orders:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to fetch orders",
    });
  }
};

/**
 * (Optional) Cancel an order
 */
const cancelOrder = async (req, res) => {
  try {
    const { orderId } = req.params;

    // Fetch the order to get the shipment ID
    const order = await prisma.order.findUnique({
      where: { id: Number(orderId) },
    });

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (order.status === "CANCELLED") {
      return res.status(400).json({ error: "Order is already cancelled" });
    }

    // Update order status to CANCELLED
    const updatedOrder = await prisma.order.update({
      where: { id: Number(orderId) },
      data: { status: "CANCELLED" },
    });

    // If there's a Shiprocket shipment, cancel it
    if (order.shiprocketShipmentId) {
      await cancelShiprocketShipment(
        { body: { shipmentId: order.shiprocketShipmentId } },
        res
      );
    }

    return res.json({ success: true, order: updatedOrder });
  } catch (error) {
    console.error("Error cancelling order:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

const getOrderDetails = async (req, res) => {
  try {
    const { orderId } = req.params;
    // const userId = req.user.id;

    const order = await prisma.order.findUnique({
      where: { orderId: orderId },
      include: {
        items: {
          include: {
            product: true, // Assuming you have a relation to the product
          },
        },
        shippingAddress: true,
      },
    });

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    // if (order.userId !== userId) {
    //   return res.status(403).json({ error: "Access denied to this order." });
    // }

    return res.json({ success: true, order });
  } catch (error) {
    console.error("Error fetching order details:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = {
  createOrderRecord,
  getUserOrders,
  cancelOrder,
  getOrderDetails,
};
