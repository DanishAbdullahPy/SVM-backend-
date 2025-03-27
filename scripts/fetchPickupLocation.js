/**
 * Fetch all pickup locations from Shiprocket.
 * @returns {Promise<Array>} List of pickup locations.
 */
const getAllPickupLocations = async () => {
  try {
    const token = await authenticateShiprocket();

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
    return response.data.data; // Adjust based on actual response structure
  } catch (error) {
    console.error(
      "Error fetching pickup locations:",
      error.response?.data || error.message
    );
    throw new Error("Failed to fetch pickup locations from Shiprocket.");
  }
};
