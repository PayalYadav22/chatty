// ==============================
// External Packages
// ==============================
import express from "express";

// ==============================
// Controllers
// ==============================
import UsersController from "../../controllers/users/users.controller.js";

// ==============================
// Middleware
// ==============================
import upload from "../../middleware/multer.middleware.js";
import authMiddleware from "../../middleware/auth/authMiddleware.middleware.js";

const router = express.Router();

router.use(authMiddleware);

/**
 * @route   GET /api/v1/profile
 * @desc    Get the current user's profile
 * @access  Private (authentication required)
 */
router.route("/profile").get(UsersController.currentUser);

/**
 * @route   PATCH /api/v1/profile/avatar
 * @desc    Update user avatar
 * @access  Private (authentication required)
 */
router
  .route("/profile/avatar")
  .patch(upload.single("avatar"), UsersController.updateUserAvatar);

/**
 * @route   DELETE /api/v1/profile/avatar
 * @desc    Delete user avatar
 * @access  Private (authentication required)
 */
router.route("/profile/avatar").delete(UsersController.deleteUserAvatar);

/**
 * @route   DELETE /api/v1/profile
 * @desc    Delete user account
 * @access  Private (authentication required)
 */
router.route("/profile").delete(UsersController.deleteUserAccount);

export default router;
