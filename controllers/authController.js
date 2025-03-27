const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const prisma = require("../DB/db.config");

// Temporary placeholders for missing dependencies
const { createUser, updateUser } = require("../helpers/userHelper") || {
  createUser: async (name, email, password, mobile) => {
    return await prisma.user.create({
      data: { name, email, password, mobile },
    });
  },
  updateUser: async (id, data) => {
    return await prisma.user.update({
      where: { id },
      data,
    });
  },
};
const { generateOTP, sendResetEmail } = require("../services/emailService") || {
  generateOTP: () => Math.floor(100000 + Math.random() * 900000).toString(),
  sendResetEmail: async (email, otp) => {
    console.log(`Sending OTP ${otp} to ${email}`); // Replace with actual email logic later
  },
};
const { validatePassword } = require("../utils/validation") || {
  validatePassword: (password) => {
    const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
    return re.test(password);
  },
};

// Register a new user
const register = async (req, res) => {
  const { name, email, password, mobile } = req.body;

  if (!name || !email || !password || !mobile) {
    return res.status(400).json({
      success: false,
      message: "All fields Required",
    });
  }

  if (!validatePassword(password)) {
    return res.status(400).json({
      success: false,
      message:
        "Password must be at least 6 characters long, include at least one uppercase letter, one lowercase letter, one number, and one special character.",
    });
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email Id already registered",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await createUser(name, email, hashedPassword, mobile);

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token,
      user: { id: user.id, name: user.name, email: user.email, mobile: user.mobile },
    });
  } catch (error) {
    console.error("Error registering user: ", error);
    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// Login user with email and password
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
      where: { email },
      include: { addresses: true },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials." });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    return res
      .status(200)
      .cookie("token", token, {
        httpOnly: true,
        sameSite: "None",
        secure: true,
        maxAge: 1 * 60 * 60 * 1000,
      })
      .json({
        success: true,
        message: "Logged in successfully.",
        user,
      });
  } catch (error) {
    console.error("Error logging User: ", error);
    res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`,
    });
  }
};

// Google OAuth login
const googleAuth = (req, res, next) => {
  passport.authenticate("google", { scope: ["profile", "email"] })(
    req,
    res,
    next
  );
};

// Google OAuth callback
const googleAuthCallback = (req, res, next) => {
  passport.authenticate("google", { failureRedirect: "/login" })(
    req,
    res,
    () => {
      const token = jwt.sign({ userId: req.user.id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      res.cookie("token", token, {
        httpOnly: true,
        sameSite: "None",
        secure: true,
        maxAge: 1 * 60 * 60 * 1000,
      });

      return res.status(200).json({
        success: true,
        message: "Logged in with Google successfully",
        user: req.user,
      });
    }
  );
};

// Logout user
const logout = async (_, res) => {
  try {
    return res
      .status(200)
      .clearCookie("token", {
        httpOnly: true,
        sameSite: "None",
        secure: true,
        path: "/",
      })
      .json({
        success: true,
        message: "User logged out successfully",
      });
  } catch (error) {
    console.error("Error logging out: ", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Update User Details Controller
const updateUserDetails = async (req, res) => {
  const { id } = req.user;
  const { name, email, mobile } = req.body;

  try {
    if (!name || !email || !mobile) {
      return res
        .status(400)
        .json({ message: "Name, email and phone no. are required fields." });
    }

    const updatedUser = await updateUser(id, { name, email, mobile });

    res.status(200).json({
      message: "User details updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

// Get user with addresses
const getUserWithAddresses = async (req, res) => {
  try {
    const { id } = req.user;
    const user = await prisma.user.findUnique({
      where: { id },
      include: { addresses: true },
    });

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

// Controller to change password
const changePassword = async (req, res) => {
  const userId = req.user.id;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Current password and new password are required.",
    });
  }

  if (!validatePassword(newPassword)) {
    return res.status(400).json({
      success: false,
      message:
        "New password must be at least 6 characters long, include at least one uppercase letter, one lowercase letter, one number, and one special character.",
    });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect.",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

    res.status(200).json({
      success: true,
      message: "Password updated successfully.",
    });
  } catch (error) {
    console.error("Error changing password: ", error);
    res.status(500).json({
      success: false,
      message: "Internal server error. Please try again later.",
    });
  }
};

// Request password reset OTP
const requestResetOTP = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json({ success: false, message: "Email is required." });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    const otp = generateOTP();

    await prisma.user.update({
      where: { email },
      data: {
        resetOtp: otp,
        resetOtpExpires: new Date(Date.now() + 15 * 60000),
      },
    });

    await sendResetEmail(email, otp);

    res.status(200).json({
      success: true,
      message: "Reset OTP sent to your email.",
    });
  } catch (error) {
    console.error("Error requesting reset OTP: ", error);
    res.status(500).json({
      success: false,
      message: "Internal server error. Please try again later.",
    });
  }
};

// Reset password using OTP
const resetPasswordWithOTP = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required." });
  }

  if (!validatePassword(newPassword)) {
    return res.status(400).json({
      success: false,
      message:
        "New password must be at least 6 characters long, include at least one uppercase letter, one lowercase letter, one number, and one special character.",
    });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    if (user.resetOtp !== otp || new Date() > user.resetOtpExpires) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await prisma.user.update({
      where: { email },
      data: { password: hashedPassword, resetOtp: null, resetOtpExpires: null },
    });

    res.status(200).json({
      success: true,
      message: "Password reset successfully.",
    });
  } catch (error) {
    console.error("Error resetting password: ", error);
    res.status(500).json({
      success: false,
      message: "Internal server error. Please try again later.",
    });
  }
};

module.exports = {
  register,
  login,
  googleAuth,
  googleAuthCallback,
  logout,
  updateUserDetails,
  getUserWithAddresses,
  changePassword,
  requestResetOTP,
  resetPasswordWithOTP,
};