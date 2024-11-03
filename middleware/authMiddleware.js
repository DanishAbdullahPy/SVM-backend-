const jwt = require("jsonwebtoken");
const { findUserById } = require("../helpers/userHelper");

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      // Get token from header
      token = req.headers.authorization.split(" ")[1];

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Get user from the token
      req.user = await findUserById(decoded.id);

      if (!req.user) {
        return res.status(401).json({ message: "Not authorized." });
      }

      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: "Not authorized, token failed." });
    }
  }

  if (!token) {
    res.status(401).json({ message: "Not authorized, no token." });
  }
};

const requireAdmin = async (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ message: "Access denied. Admins only." });
  }
  next();
};

module.exports = { protect, requireAdmin };
