// services/shiprocketService.js

const axios = require("axios");

const SHIPROCKET_BASE_URL =
  process.env.SHIPROCKET_BASE_URL || "https://apiv2.shiprocket.in/v1/external";
const SHIPROCKET_EMAIL = process.env.SHIPROCKET_EMAIL;
const SHIPROCKET_PASSWORD = process.env.SHIPROCKET_PASSWORD;

let shiprocketToken = null;
let tokenExpiry = null;

/**
 * Authenticate with Shiprocket
 */
const authenticateShiprocket = async () => {
  try {
    const response = await axios.post(`${SHIPROCKET_BASE_URL}/auth/login`, {
      email: SHIPROCKET_EMAIL,
      password: SHIPROCKET_PASSWORD,
    });

    if (response.data.token) {
      console.log("Shiprocket authenticated successfully.");
      shiprocketToken = response.data.token;

      // Assuming the response contains an expiry time (e.g., expires_in in seconds)
      const expiresIn = response.data.expires_in || 3600; // Default to 1 hour
      tokenExpiry = Date.now() + expiresIn * 1000;

      return shiprocketToken;
    } else {
      throw new Error("Authentication failed: No token received.");
    }
  } catch (error) {
    console.error(
      "Error authenticating with Shiprocket:",
      error.response?.data || error.message
    );
    throw new Error("Shiprocket authentication failed.");
  }
};

/**
 * Get a valid Shiprocket token
 */
async function getShiprocketToken() {
  if (shiprocketToken && tokenExpiry > Date.now()) {
    return shiprocketToken;
  }
  return await authenticateShiprocket();
}

/**
 * Fetch all pickup locations from Shiprocket.
 * @returns {Promise<Object>} Object containing 'shipping_address' array.
 */
const getAllPickupLocations = async () => {
  try {
    const token = await getShiprocketToken();

    const response = await axios.get(
      `${SHIPROCKET_BASE_URL}/settings/company/pickup`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    console.log(
      "Available Pickup Locations:",
      JSON.stringify(response.data, null, 2)
    );

    return response.data; // Ensure that the function returns the entire object
  } catch (error) {
    console.error(
      "Error fetching pickup locations:",
      error.response?.data || error.message
    );
    throw new Error("Failed to fetch pickup locations from Shiprocket.");
  }
};

/**
 * Create a Shiprocket order
 */
async function createShiprocketOrder(orderData) {
  try {
    const token = await getShiprocketToken();

    const response = await axios.post(
      `${SHIPROCKET_BASE_URL}/orders/create/adhoc`,
      orderData,
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }
    );

    console.log("Shiprocket create order response:", response.data);

    return response.data;
  } catch (error) {
    console.error(
      "Error creating Shiprocket order:",
      error.response?.data || error.message
    );
    throw new Error("Shiprocket Order Creation Failed");
  }
}

/**
 * Track a Shiprocket shipment
 */
async function trackShipment(shipmentId) {
  try {
    const token = await getShiprocketToken();
    const response = await axios.get(
      `${SHIPROCKET_BASE_URL}/courier/track/shipment/${shipmentId}`, //https://apiv2.shiprocket.in/v1/external/courier/track/shipment/{shipmentId}
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );
    console.log("Shiprocket tracking response:", response.data);
    return response.data;
  } catch (error) {
    console.error(
      "Error tracking shipment:",
      error.response?.data || error.message
    );
    throw new Error("Shiprocket Shipment Tracking Failed");
  }
}

/**
 * Cancel a Shiprocket shipment
 */
async function cancelShipment(shipmentId) {
  try {
    const token = await getShiprocketToken();
    const response = await axios.post(
      `${SHIPROCKET_BASE_URL}/shipments/cancel`,
      { shipment_id: shipmentId },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      }
    );
    console.log("Shiprocket cancellation response:", response.data);
    return response.data;
  } catch (error) {
    console.error(
      "Error cancelling shipment:",
      error.response?.data || error.message
    );
    throw new Error("Shiprocket Shipment Cancellation Failed");
  }
}

/**
 * Get all pickup locations
 * @returns {Promise<Object>} The entire response object containing shipping_address and other details.
 */
module.exports = {
  createShiprocketOrder,
  trackShipment,
  cancelShipment,
  getAllPickupLocations,
};
