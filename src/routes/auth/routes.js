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
  loginLimiter,
  forgotPasswordLimiter,
  generalLimiter,
} from "../../middleware/rateLimiter.middleware.js";
import authMiddleware from "../../middleware/auth/authMiddleware.middleware.js";
import {
  isAdminOrSuperAdmin,
  isSuperAdmin,
} from "../../middleware/auth/roleMiddleware.js";
import validateRequest from "../../middleware/validateRequest.middleware.js";

// ==============================
// Validations
// ==============================
import {
  loginUserSchema,
  registerUserSchema,
  verifyEmailSchema,
  resetPasswordTokenSchema,
  resetPasswordOtpSchema,
} from "../../validations/auth.validation.js";

const router = express.Router();

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user with optional avatar upload
 * @access  Public
 */
router
  .route("/register")
  .post(
    upload.single("avatar"),
    validateRequest(registerUserSchema),
    AuthController.registerUser
  );

/**
 * @route   POST /api/v1/auth/verify-email
 * @desc    Verify a new user email with OTP
 * @access  Public
 */
router
  .route("/verify-email")
  .post(
    generalLimiter,
    validateRequest(verifyEmailSchema),
    AuthController.verifyUser
  );

/**
 * @route   POST /api/v1/auth/login
 * @desc    Log in an existing user
 * @access  Public
 */
router
  .route("/login")
  .post(validateRequest(loginUserSchema), AuthController.loginUser);

/**
 * @route   POST /api/v1/auth/resend-otp
 * @desc    Resend OTP for email verification
 * @access  Public
 */
router.route("/resend-otp").post(generalLimiter, AuthController.resendOTP);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Initiate password reset by sending email to user
 * @access  Public
 */
router.route("/forgot-password").post(AuthController.forgotUserPassword);

/**
 * @route   POST /api/v1/auth/verify-security-question
 * @desc    Verify security question answer to proceed with password reset
 * @access  Public
 */
router
  .route("/verify-security-question")
  .post(generalLimiter, AuthController.verifySecurityQuestion);

/**
 * @route   POST /api/v1/auth/reset-password-otp
 * @desc    Reset user password using valid OTP
 * @access  Public
 */
router
  .route("/reset-password-otp")
  .post(
    generalLimiter,
    validateRequest(resetPasswordOtpSchema),
    AuthController.resetUserPasswordWithOTP
  );

/**
 * @route   POST /api/v1/auth/reset-password/:token
 * @desc    Reset user password using valid token
 * @access  Public
 */
router
  .route("/reset-password")
  .post(
    validateRequest(resetPasswordTokenSchema),
    generalLimiter,
    AuthController.resetUserPasswordWithToken
  );

/**
 * @route   POST /api/v1/auth/refresh-token
 * @desc    Refresh JWT access token using refresh token
 * @access  Public
 */
router
  .route("/refresh-token")
  .get(generalLimiter, AuthController.refreshUserToken);

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Log out the authenticated user and blacklist their JWT token
 * @access  Public
 */
router.route("/logout").get(generalLimiter, AuthController.logoutUser);

// ==============================
// Secure Routes
// ==============================
router.use(authMiddleware);

// ==============================
// Token Blacklist Routes
// ==============================

/**
 * @route   GET /api/v1/token/blacklist
 * @desc    Get all blacklisted tokens
 * @access  Private (Admin or Super Admin)
 */
router
  .route("/token/blacklist")
  .get(
    isAdminOrSuperAdmin,
    generalLimiter,
    AuthController.getAllBlacklistedTokens
  );

/**
 * @route   DELETE /api/v1/token/blacklist
 * @desc    Remove a token from the blacklist
 * @access  Private (Admin or Super Admin)
 */
router
  .route("/token/blacklist")
  .delete(isSuperAdmin, generalLimiter, AuthController.removeBlacklistToken);

/**
 * @route   GET /api/v1/token/blacklist/count
 * @desc    Get count of blacklisted tokens
 * @access  Private (Admin or Super Admin)
 */
router
  .route("/token/blacklist/count")
  .get(isAdminOrSuperAdmin, generalLimiter, AuthController.getBlacklistCount);

// ==============================
// Session Routes
// ==============================

/**
 * @route   POST /api/v1/session
 * @desc    Create a new session for a user
 * @access  Private
 */
router
  .route("/session")
  .post(isSuperAdmin, generalLimiter, AuthController.createSession);

/**
 * @route   GET /api/v1/session/user/:userId
 * @desc    Get all sessions for a specific user
 * @access  Private (Admin or User)
 */
router
  .route("/session")
  .get(isAdminOrSuperAdmin, generalLimiter, AuthController.getSessionsForUser);

/**
 * @route   GET /api/v1/session/:sessionId
 * @desc    Get a session by its ID
 * @access  Private
 */
router
  .route("/session/:sessionId")
  .get(isAdminOrSuperAdmin, generalLimiter, AuthController.getSessionById);

/**
 * @route   PATCH /api/v1/session/invalidate/:sessionId
 * @desc    Invalidate a specific session
 * @access  Private (Admin or User)
 */
router
  .route("/session/invalidate/:sessionId")
  .get(isSuperAdmin, generalLimiter, AuthController.invalidateSession);

/**
 * @route   DELETE /api/v1/session/:sessionId
 * @desc    Delete a specific session
 * @access  Private (Admin or User)
 */
router
  .route("/session/:sessionId")
  .delete(isSuperAdmin, generalLimiter, AuthController.deleteSession);

/**
 * @route   GET /api/v1/session/active/count
 * @desc    Get the count of active sessions
 * @access  Private (Admin)
 */
router
  .route("/session/active/count")
  .get(
    isAdminOrSuperAdmin,
    generalLimiter,
    AuthController.getActiveSessionCount
  );

/**
 * @route   DELETE /api/v1/session/logout/all
 * @desc    Log out all sessions for the authenticated user
 * @access  Private
 */
router
  .route("/session/logout/all")
  .delete(isSuperAdmin, generalLimiter, AuthController.logoutAllSessions);

/**
 * @route   DELETE /api/v1/session/cleanup/expired
 * @desc    Clean up expired sessions
 * @access  Private (Admin)
 */
router
  .route("/session/cleanup/expired")
  .delete(isSuperAdmin, generalLimiter, AuthController.cleanupExpiredSessions);

export default router;
