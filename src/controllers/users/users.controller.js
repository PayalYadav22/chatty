// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";
import { StatusCodes } from "http-status-codes";

// ==============================
// Models
// ==============================
import User from "../../models/user.model.js";

// ==============================
// Middleware
// ==============================
import asyncHandler from "../../middleware/asyncHandler.middleware.js";

// ==============================
// Utils
// ==============================
import sendEmail from "../../utils/email.js";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import { logAudit, logActivity } from "../../utils/logger.js";

// ==============================
// Config / Services
// ==============================
import {
  uploadFileToCloudinary,
  deleteFileToCloudinary,
} from "../../config/cloudinary.config.js";

// ==============================
// Helper Functions
// ==============================
const deleteAvatar = async (user) => {
  const avatarFilePath = user.avatar?.publicId;
  if (avatarFilePath) {
    const deletionResult = await deleteFileToCloudinary(avatarFilePath);
    if (!deletionResult) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Error deleting avatar image from Cloudinary."
      );
    }
  }
};

const verifyUser = (userId) => {
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user ID.");
  }
};

// ==============================
// Controller Function
// ==============================
const UsersController = {
  currentUser: asyncHandler(async (req, res) => {
    const userId = req.user?._id;
    verifyUser(userId);

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId)
      .select("-password -token -userName -__v")
      .lean();

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Logging activity for the current user
    await logActivity({
      userId: user._id,
      action: "VIEW_PROFILE",
      description: "User viewed their profile.",
      req,
    });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: user._id,
        fullName: user.fullName,
        userName: user.userName,
        email: user.email,
        phone: user.phone,
        avatar: user.avatar,
        role: user.role,
      },
      "Current user profile fetched successfully."
    ).send(res);
  }),

  updateUserProfile: asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { fullName, userName } = req.body;

    // Validate required fields
    if (!fullName || !userName) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Missing required fields.");
    }

    const oldUser = await User.findById(userId).lean();

    if (!oldUser) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { fullName, userName },
      { new: true, runValidators: true }
    );

    if (!user) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Error updating user credentials."
      );
    }

    // Logging activity for profile update
    await logActivity({
      userId,
      action: "UPDATE_PROFILE",
      description: "User updated their profile information.",
      target: user._id,
      req,
      additionalData: { updatedFields: { fullName, userName } },
    });

    // Logging audit for profile changes
    const changes = {};
    if (oldUser.fullName !== user.fullName) {
      changes.fullName = { old: oldUser.fullName, new: user.fullName };
    }
    if (oldUser.userName !== user.userName) {
      changes.userName = { old: oldUser.userName, new: user.userName };
    }

    await logAudit({
      actorId: userId,
      targetId: userId,
      targetModel: "User",
      eventType: "UPDATE_PROFILE",
      description: "Updated user profile fields",
      changes,
      req,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { id: user._id, fullName: user.fullName, userName: user.userName },
      "User updated successfully."
    ).send(res);
  }),

  updateUserAvatar: asyncHandler(async (req, res) => {
    const userId = req.user?.id;

    verifyUser(userId);

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const avatarFilePath = req.file?.path;

    if (!avatarFilePath) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "No avatar image provided.");
    }

    const previousAvatar = user.avatar || null;

    const avatar = await uploadFileToCloudinary(avatarFilePath);

    if (previousAvatar?.publicId) {
      await deleteFileToCloudinary(previousAvatar.publicId);
    }

    // Updating the avatar
    user.avatar = {
      url: avatar.secure_url,
      publicId: avatar.public_id,
    };

    await user.save({ validateBeforeSave: false });

    // Logging activity and audit for avatar change
    await logActivity({
      userId,
      action: "UPDATE_AVATAR",
      description: "User updated their avatar.",
      target: userId,
      req,
      additionalData: { newAvatarUrl: avatar.secure_url },
    });

    await logAudit({
      actorId: userId,
      targetId: userId,
      targetModel: "User",
      eventType: "UPDATE_AVATAR",
      description: "User changed avatar image.",
      changes: {
        before: previousAvatar,
        after: { url: avatar.secure_url, publicId: avatar.public_id },
      },
      req,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { url: avatar.secure_url, publicId: avatar.public_id },
      "Avatar updated successfully."
    ).send(res);
  }),

  changePassword: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    const { oldPassword, newPassword } = req.body;

    verifyUser(userId);

    if (oldPassword === newPassword) {
      throw new ApiError(
        StatusCodes.CONFLICT,
        "New password must be different from the old one."
      );
    }

    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const isValid = await user.comparePassword(oldPassword);
    if (!isValid) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid current password.");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    // Send password change email
    try {
      await sendEmail({
        to: user.email,
        subject: "Security Alert: Password Changed",
        template: "passwordChanged",
        context: { name: user.fullName },
      });
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to send password change email."
      );
    }

    // Logging activity and audit for password change
    await logActivity({
      userId,
      action: "CHANGE_PASSWORD",
      description: "User changed password.",
      target: userId,
      req,
      additionalData: { changeType: "password", sensitivity: "high" },
    });

    await logAudit({
      actorId: userId,
      targetId: userId,
      targetModel: "User",
      eventType: "CHANGE_PASSWORD",
      description: "Password was changed.",
      changes: { field: "password" },
      req,
    });

    return new ApiResponse(
      StatusCodes.OK,
      "Password changed successfully."
    ).send(res);
  }),

  deleteUserAvatar: asyncHandler(async (req, res) => {
    const userId = req.user?.id;
    verifyUser(userId);

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    await deleteAvatar(user);

    user.avatar = undefined;
    await user.save({ validateBeforeSave: false });

    // Logging activity and audit for avatar deletion
    await logActivity({
      userId,
      action: "DELETE_AVATAR",
      description: "User deleted their avatar image.",
      req,
    });

    await logAudit({
      actorId: userId,
      targetId: userId,
      targetModel: "User",
      eventType: "DELETE_AVATAR",
      description: "User avatar image deleted.",
      changes: { avatar: "deleted" },
      req,
    });

    return new ApiResponse(StatusCodes.OK, "Avatar deleted successfully.").send(
      res
    );
  }),

  deleteUserAccount: asyncHandler(async (req, res) => {
    const userId = req.user?.id;

    verifyUser(userId);

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    await logActivity({
      userId,
      action: "DELETE_ACCOUNT",
      description: "User deleted their account.",
      target: userId,
      req,
    });

    await logAudit({
      actorId: userId,
      targetId: userId,
      targetModel: "User",
      eventType: "DELETE_ACCOUNT",
      description: "User account deleted along with avatar.",
      changes: { avatar: user.avatar ? "deleted" : "none" },
      req,
    });

    await deleteAvatar(user);
    await User.findByIdAndDelete(userId);

    return new ApiResponse(
      StatusCodes.OK,
      "User account deleted successfully."
    ).send(res);
  }),

  getUserForSideBar: asyncHandler(async (req, res) => {
    const userId = req.user?.id;

    verifyUser(userId);

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const users = await User.find({ _id: { $ne: userId } }).select(
      "-password -token -passwordResetToken -passwordResetTokenExpiration -otp -otpExpiry -otpAttempts -twoFactorSecret"
    );

    await logActivity({
      userId,
      action: "LIST_PROFILE",
      description: "User fetched data for sidebar",
      target: users.map((user) => user._id),
      req,
    });

    return new ApiResponse(
      StatusCodes.OK,
      users.map((user) => ({
        id: user._id,
        fullName: user.fullName,
        userName: user.userName,
        email: user.email,
        phone: user.phone,
        avatar: user.avatar,
        role: user.role,
      })),
      "User data retrieved successfully."
    ).send(res);
  }),
};

export default UsersController;
