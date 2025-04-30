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

const router = express.Router();

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user with optional avatar upload
 * @access  Public
 */
router
  .route("/register")
  .post(upload.single("avatar"), AuthController.registerUser);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Log in an existing user
 * @access  Public
 */
router.route("/login").post(AuthController.loginUser);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Initiate password reset by sending email to user
 * @access  Public
 */
router.route("/forgot-password").post(AuthController.forgotUserPassword);

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

export default router;
