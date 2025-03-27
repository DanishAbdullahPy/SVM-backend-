// controllers/shiprocketController.js

const {
  createShiprocketOrder,
  trackShipment,
  cancelShipment,
  getAllPickupLocations,
} = require("../services/shiprocketService");
const prisma = require("../DB/db.config");

/**
 * Create a Shiprocket order
 * @param {Object} orderData - The payload for Shiprocket order creation
 * @param {Object} res - Express response object
 * @returns {Object} - Contains order_id and shipment_id
 */
const handleCreateShiprocketOrder = async (orderData, res) => {
  try {
    console.log("Creating Shiprocket Order with payload:", orderData);

    // Create Shiprocket order via service
    const shiprocketRes = await createShiprocketOrder(orderData);

    console.log("Shiprocket Order Creation Response:", shiprocketRes);

    // Ensure Shiprocket responded with order and shipment IDs
    const { order_id, shipment_id } = shiprocketRes;

    if (!order_id || !shipment_id) {
      console.log("Incomplete Shiprocket response:", shiprocketRes);
      throw new Error("Incomplete Shiprocket response.");
    }

    // Convert IDs to strings
    const shiprocketOrderId = order_id.toString();
    const shiprocketShipmentId = shipment_id.toString();

    // Update the corresponding Order in the DB with Shiprocket IDs
    const updatedOrder = await prisma.order.update({
      where: { orderId: orderData.order_id },
      data: {
        shiprocketOrderId, // String
        shiprocketShipmentId, // String
      },
    });

    console.log("Order updated with Shiprocket IDs:", updatedOrder);

    return {
      shiprocketOrderId,
      shiprocketShipmentId,
    };
  } catch (error) {
    console.error("Error in handleCreateShiprocketOrder:", error.message);
    throw new Error("Shiprocket Order Creation Failed");
  }
};

/**
 * Track a Shiprocket shipment
 * GET /api/shiprocket/track/:shipmentId
 */
// const handleTrackShipment = async (req, res) => {
//   try {
//     const { shipmentId } = req.params;

//     if (!shipmentId) {
//       return res.status(400).json({ error: "Shipment ID is required." });
//     }

//     const trackingInfo = await trackShipment(shipmentId);

//     return res.json({
//       status: "success",
//       tracking: trackingInfo,
//     });
//   } catch (error) {
//     console.error("Error tracking Shiprocket shipment:", error);
//     return res.status(500).json({ error: "Internal Server Error" });
//   }
// };

const handleTrackShipment = async (req, res) => {
  try {
    const { shipmentId } = req.params;

    if (!shipmentId) {
      return res.status(400).json({ error: "Shipment ID is required." });
    }

    // Fetch tracking details from Shiprocket
    const trackingInfo = await trackShipment(shipmentId);
    console.log("Shiprocket tracking response:", trackingInfo);

    // Fetch order details from the database using `shipmentId`
    const order = await prisma.order.findFirst({
      where: { shiprocketShipmentId: shipmentId },
      include: {
        items: { include: { product: true } },
      },
    });

    console.log("Fetched Order:", order); // ✅ Debugging Log

    if (!order) {
      return res
        .status(404)
        .json({ error: "Order not found for this shipment." });
    }

    const responseData = {
      status: "success",
      tracking: trackingInfo,
      orderDetails: order,
    };

    console.log("Final API Response:", responseData); // ✅ Debugging Log
    res.setHeader("Cache-Control", "no-store"); // ✅ Prevents 304 Caching Issues
    return res.json(responseData);
  } catch (error) {
    console.error("Error tracking Shiprocket shipment:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

// const handleTrackShipment = async (req, res) => {
//   try {
//     const { shipmentId } = req.params;

//     if (!shipmentId) {
//       return res.status(400).json({ error: "Shipment ID is required." });
//     }

//     // Fetch tracking details from Shiprocket
//     const trackingInfo = await trackShipment(shipmentId);

//     // Fetch order details from the database using `shipmentId`
//     const order = await prisma.order.findFirst({
//       where: { shiprocketShipmentId: shipmentId }, // Use findFirst instead of findUnique
//       include: {
//         orderItems: {
//           include: { product: true }, // Include product details
//         },
//       },
//     });

//     if (!order) {
//       return res
//         .status(404)
//         .json({ error: "Order not found for this shipment." });
//     }

//     return res.json({
//       status: "success",
//       tracking: trackingInfo,
//       orderDetails: order, // Attach order details here
//     });
//   } catch (error) {
//     console.error("Error tracking Shiprocket shipment:", error);
//     return res.status(500).json({ error: "Internal Server Error" });
//   }
// };

// const handleTrackShipment = async (req, res) => {
//   try {
//     const { shipmentId } = req.params;

//     if (!shipmentId) {
//       return res.status(400).json({ error: "Shipment ID is required." });
//     }

//     // Fetch tracking details from Shiprocket
//     const trackingInfo = await trackShipment(shipmentId);

//     // Fetch order details from the database using `shipmentId`
//     const order = await prisma.order.findUnique({
//       where: {
//         shiprocketShipmentId: shipmentId, // Use `shipmentId` as `shiprocketShipmentId`
//       },
//       include: {
//         orderItems: {
//           include: {
//             product: true, // Include `product` relation
//           },
//         },
//       },
//     });

//     if (!order) {
//       return res
//         .status(404)
//         .json({ error: "Order not found for this shipment." });
//     }

//     return res.json({
//       status: "success",
//       tracking: trackingInfo,
//       orderDetails: order, // Use `order` object as `orderDetails`
//     });
//   } catch (error) {
//     console.error(
//       "Error tracking Shiprocket shipment:",
//       error.response?.data || error.message
//     );
//     return res.status(500).json({ error: "Internal Server Error" });
//   }
// };

/**
 * Cancel a Shiprocket shipment
 * POST /api/shiprocket/cancel
 */
const handleCancelShipment = async (req, res) => {
  try {
    const { shipmentId } = req.body;

    if (!shipmentId) {
      return res
        .status(400)
        .json({ error: "Missing shipmentId in request body." });
    }

    const cancellationResponse = await cancelShipment(shipmentId);

    // Update order status if needed
    const order = await prisma.order.findUnique({
      where: { shiprocketShipmentId: shipmentId },
    });

    if (order) {
      await prisma.order.update({
        where: { id: order.id },
        data: { status: "CANCELLED" },
      });
    }

    return res.json({
      status: "success",
      message: "Shipment cancelled successfully",
      cancellation: cancellationResponse,
    });
  } catch (error) {
    console.error("Error cancelling Shiprocket shipment:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = {
  handleCreateShiprocketOrder,
  handleTrackShipment,
  handleCancelShipment,
};
