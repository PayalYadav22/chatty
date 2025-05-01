// ==============================
// External Packages
// ==============================
import express from "express";

// ==============================
// Controllers
// ==============================
import AuthController from "../../controllers/auth/auth.controller.js";

// ==============================
// Middleware
// ==============================
import upload from "../../middleware/multer.middleware.js";
import {
  registerLimiter,
  authLimiter,
} from "../../middleware/rateLimiter.middleware.js";

const router = express.Router();

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user with optional avatar upload
 * @access  Public
 */
router
  .route("/register")
  .post(upload.single("avatar"), registerLimiter, AuthController.registerUser);

/**
 * @route   POST /api/v1/auth/verify-email
 * @desc    Verify a new user email with OTP
 * @access  Public
 */
router.route("/verify-email").post(AuthController.verifyUser);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Log in an existing user
 * @access  Public
 */
router.route("/login").post(authLimiter, AuthController.loginUser);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Initiate password reset by sending email to user
 * @access  Public
 */
router
  .route("/forgot-password")
  .post(authLimiter, AuthController.forgotUserPassword);

/**
 * @route   POST /api/v1/auth/reset-password/:token
 * @desc    Reset user password using valid token
 * @access  Public
 */
router.route("/reset-password/:token").post(AuthController.resetUserPassword);

/**
 * @route   POST /api/v1/auth/refresh-token
 * @desc    Refresh JWT access token using refresh token
 * @access  Public
 */
router.route("/refresh-token").post(AuthController.refreshUserToken);

/**
 * @route   POST /api/v1/auth/block-token
 * @desc    Blacklist a JWT refresh/access token to prevent further use
 * @access  Public
 */
router.route("/block-token").post(AuthController.blacklistToken);

export default router;
