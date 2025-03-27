// controllers/razorpayController.js
const razorpay = require("../services/razorpay");
const crypto = require("crypto");
const prisma = require("../DB/db.config");
const { handleCreateShiprocketOrder } = require("./shiprocketController");
const { getAllPickupLocations } = require("../services/shiprocketService");

/**
 * Create a new Razorpay order
 * POST /api/razorpay/create-order
 */
const createOrder = async (req, res) => {
  try {
    const { amount, currency, receipt, userId } = req.body;

    if (!amount || !currency || !receipt || !userId) {
      return res.status(400).json({
        error: "Missing required fields: amount, currency, receipt, userId",
      });
    }

    // Create an order on Razorpay
    const options = {
      amount, // in paise
      currency, // e.g. "INR"
      receipt, // e.g. "receipt_123"
    };
    const order = await razorpay.orders.create(options);

    console.log("Razorpay Order ID:", order.id); // Add this line

    // Store the order in your DB with status="CREATED"
    const newOrder = await prisma.order.create({
      data: {
        orderId: order.id, // same as Razorpay order.id
        userId,
        receipt,
        amount, // in paise
        currency,
        status: "CREATED",
      },
    });

    console.log("New Order Created:", newOrder); // Add this line

    // Return both the Razorpay order + your DB record
    return res.status(201).json({ order, newOrder });
  } catch (error) {
    console.error("Error creating Razorpay order:", error);

    if (error.error && error.error.description) {
      return res.status(400).json({ error: error.error.description });
    }
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

/**
 * Verify Razorpay payment signature
 * POST /api/razorpay/verify-payment
 */
const verifyPayment = async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      userId,
      cartItems,
      amount,
      currency,
      receipt,
      billing_customer_name,
      billing_last_name,
      billing_address,
      billing_city,
      billing_pincode,
      billing_state,
      billing_country,
      billing_email,
      billing_phone,
      length,
      breadth,
      height,
      weight,
      addressId,
    } = req.body;

    // Log the necessary fields for debugging (exclude sensitive info)
    console.log("Received verifyPayment payload:", {
      razorpay_order_id,
      razorpay_payment_id,
      userId,
      amount,
      currency,
      receipt,
      billing_customer_name,
      billing_address,
      billing_city,
      billing_pincode,
      billing_state,
      // Exclude fields like billing_email and billing_phone
    });

    // Validate all required fields
    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature ||
      !userId ||
      !cartItems ||
      !amount ||
      !currency ||
      !receipt ||
      !billing_customer_name ||
      !billing_address ||
      !billing_city ||
      !billing_pincode ||
      !billing_state ||
      !billing_email ||
      !billing_phone ||
      !length ||
      !breadth ||
      !height ||
      !weight ||
      !addressId
    ) {
      return res
        .status(400)
        .json({ error: "Missing required payment fields." });
    }

    console.log("Verifying payment for Order ID:", razorpay_order_id);

    // Step 1: Validate Razorpay signature
    const sign = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign)
      .digest("hex");

    console.log("Expected Signature:", expectedSignature);
    console.log("Received Signature:", razorpay_signature);

    if (expectedSignature !== razorpay_signature) {
      console.log("Invalid payment signature.");
      return res
        .status(400)
        .json({ status: "failure", message: "Invalid payment signature." });
    }

    // Step 2: Payment is verified => update the existing order to "PAID"
    // Fetch the selected shipping address from the database
    const shippingAddress = await prisma.address.findUnique({
      where: { id: addressId },
    });

    if (!shippingAddress) {
      console.log("Shipping address not found.");
      return res
        .status(404)
        .json({ status: "failure", message: "Shipping address not found." });
    }
    // Update the order with status "PAID" and associate shipping address
    const updatedOrder = await prisma.order.update({
      where: { orderId: razorpay_order_id },
      data: {
        status: "PAID",
        items: {
          create: cartItems.map((item) => ({
            productId: item.productId,
            quantity: item.quantity,
            price: item.price,
          })),
        },
        shippingAddress: {
          connect: { id: addressId }, // Associate existing shipping address
        },
      },
      include: { items: true, shippingAddress: true },
    });

    console.log("Order updated to PAID:", updatedOrder);

    // Step 3: Fetch and Validate Pickup Location
    const availablePickupLocations = await getAllPickupLocations();

    console.log("Available Pickup Locations:", availablePickupLocations);

    // Access the 'shipping_address' array within 'data'
    const shippingAddresses = availablePickupLocations.data.shipping_address;

    if (!Array.isArray(shippingAddresses)) {
      console.log("Invalid structure for pickup locations.");
      return res.status(500).json({
        error: "Internal Server Error: Invalid pickup locations structure.",
      });
    }

    // Extract the 'pickup_location' values
    const pickupLocationNames = shippingAddresses.map(
      (location) => location.pickup_location
    );

    console.log("Pickup Location Names:", pickupLocationNames);

    // Find if the desired pickup location exists
    const desiredPickupLocation = pickupLocationNames.find(
      (name) => name === process.env.SHIPROCKET_PICKUP_LOCATION
    );

    if (!desiredPickupLocation) {
      console.log(
        `Invalid Pickup Location: "${process.env.SHIPROCKET_PICKUP_LOCATION}". It does not match any registered pickup locations.`
      );
      return res.status(400).json({
        error:
          "Invalid Pickup Location. Please verify your SHIPROCKET_PICKUP_LOCATION environment variable.",
      });
    }

    // Step 4: Create Shiprocket Order
    const shiprocketPayload = {
      order_id: updatedOrder.orderId,
      pickup_location: desiredPickupLocation, // Use the exact match
      billing_customer_name: billing_customer_name, // Ensure this is a string
      billing_last_name: billing_last_name || "",
      billing_address: billing_address,
      billing_city: billing_city,
      billing_pincode: billing_pincode,
      billing_state: billing_state,
      billing_country: billing_country || "India",
      billing_email: billing_email,
      billing_phone: billing_phone,
      order_items: cartItems.map((item) => ({
        name: item.productName || "Product",
        sku: item.productId,
        units: item.quantity,
        selling_price: item.price,
      })),
      payment_method: "Prepaid", // Adjust based on your payment method
      order_date: new Date().toISOString().split("T")[0], // Format: YYYY-MM-DD
      sub_total: amount / 100, // Assuming 'amount' is in paise
      shipping_is_billing: true, // Assuming shipping address is same as billing
      length: Number(length),
      breadth: Number(breadth),
      height: Number(height),
      weight: Number(weight),
    };

    console.log("Shiprocket Payload:", shiprocketPayload);

    // Call Shiprocket to create the order
    const shiprocketRes = await handleCreateShiprocketOrder(
      shiprocketPayload,
      res
    );

    console.log("Shiprocket Response:", shiprocketRes);

    // Check if Shiprocket order was created successfully
    if (!shiprocketRes || !shiprocketRes.shiprocketShipmentId) {
      console.log("Failed to create Shiprocket shipment.");
      throw new Error("Failed to create Shiprocket order.");
    }

    // Return success response
    return res.json({
      status: "success",
      message: "Payment verified successfully & Shiprocket order created",
      order: updatedOrder,
      shiprocket: shiprocketRes,
    });
  } catch (error) {
    console.error("Error verifying Razorpay payment:", error.message);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

module.exports = {
  createOrder,
  verifyPayment,
};
