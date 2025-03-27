const jwt = require("jsonwebtoken");

const isAuthenticated = async (req, res, next) => {
  try {
    // Log the incoming request method
    console.log(`Incoming Request Method: ${req.method}`);

    // Bypass OPTIONS requests
    if (req.method === "OPTIONS") {
      console.log("Bypassing authentication for OPTIONS request.");
      return next();
    }

    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
    if (!token) {
      console.log("Authentication failed: No token provided.");
      return res.status(401).json({
        success: false,
        message: "User not authenticated",
      });
    }

    // Verify and decode the token
    const decode = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded JWT Payload:", decode); // Debugging line

    if (!decode) {
      console.log("Authentication failed: Invalid token.");
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }

    // Adjust based on the actual payload
    req.user = { id: decode.userId || decode.id };
    console.log(`Authenticated User ID: ${req.user.id}`);

    next();
  } catch (error) {
    console.error("Error in authentication middleware:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
};

module.exports = { isAuthenticated };
