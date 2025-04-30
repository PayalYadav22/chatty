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
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";

// ==============================
// Config / Services
// ==============================
import {
  uploadFileToCloudinary,
  deleteFileToCloudinary,
} from "../../config/cloudinary.config.js";

const UsersController = {
  currentUser: asyncHandler(async (req, res) => {
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId)
      .select("-password -token -userName -__v")
      .lean();

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: user._id,
        fullName: user.fullName,
        userName: user.userName,
        email: user.email,
        phone: user.phone,
        avatar: user.avatar,
      },
      "Current user fetched successfully."
    ).send(res);
  }),

  updateUserAvatar: asyncHandler(async (req, res) => {
    const userId = req.user?.id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

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

    const avatar = await uploadFileToCloudinary(avatarFilePath);

    if (user.avatar?.publicId) {
      await deleteFileToCloudinary(user.avatar.publicId);
    }

    user.avatar = {
      url: avatar.secure_url,
      publicId: avatar.public_id,
    };

    await user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        url: avatar.secure_url,
        publicId: avatar.public_id,
      },
      "Avatar updated successfully."
    ).send(res);
  }),

  deleteUserAvatar: asyncHandler(async (req, res) => {
    const userId = req.user?.id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const avatarFilePath = user.avatar?.publicId;

    if (!avatarFilePath) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "No avatar image to delete.");
    }

    const avatarDeletionResult = await deleteFileToCloudinary(avatarFilePath);

    if (!avatarDeletionResult) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Error deleting avatar image from Cloudinary."
      );
    }

    user.avatar = undefined;

    user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      "Avatar image deleted successfully."
    ).send(res);
  }),

  deleteUserAccount: asyncHandler(async (req, res) => {
    const userId = req.user?.id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid User ID.");
    }

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    if (user.avatar?.publicId) {
      const avatarDeletionResult = await deleteFileToCloudinary(
        user.avatar.publicId
      );
      if (!avatarDeletionResult) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Error deleting avatar from Cloudinary."
        );
      }
    }

    await User.findByIdAndDelete(userId);

    return new ApiResponse(
      StatusCodes.OK,
      "User account deleted successfully."
    ).send(res);
  }),

  getUserForSideBar: asyncHandler(async (req, res) => {
    const userId = req.user?.id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid User ID.");
    }

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.find({ _id: { $ne: userId } }).select(
      "-password -token -passwordResetToken -passwordResetTokenExpiration"
    );

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
      "User data retrieved successfully."
    ).send(res);
  }),
};

export default UsersController;
