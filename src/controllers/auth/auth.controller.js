// ==============================
// External Packages
// ==============================
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
  deleteFileToCloudinary,
  uploadFileToCloudinary,
} from "../../config/cloudinary.config.js";

// ==============================
// Constants
// ==============================
import {
  options,
  expireTime,
  refreshTokenSecret,
} from "../../constants/constant.js";

// ==============================
// Logger
// ==============================
import logger from "../../logger/logger.js";

const AuthController = {
  registerUser: asyncHandler(async (req, res) => {
    const { fullName, email, phone, userName, password } = req.body;

    if ([fullName, email, phone, userName, password].some((field) => !field)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "All fields (full name, email, username, phone, and password) are required to register."
      );
    }

    const avatarLocalFilePath = req?.file?.path;

    if (!avatarLocalFilePath) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Avatar image file is missing. Please upload an image."
      );
    }

    const avatar = await uploadFileToCloudinary(avatarLocalFilePath);

    if (!avatar) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Failed to upload avatar image. Please try again."
      );
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { userName }, { phone }],
    });

    if (existingUser) {
      throw new ApiError(
        StatusCodes.CONFLICT,
        "A user with the provided email or username already exists."
      );
    }

    const user = await User.create({
      fullName,
      email,
      userName,
      phone,
      password,
      avatar: {
        url: avatar.secure_url,
        publicId: avatar.public_id,
      },
    });

    if (!user) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "User creation failed. Please try again later."
      );
    }

    try {
      const { accessToken, refreshToken } = await User.generateToken(user?._id);

      res
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options);

      return new ApiResponse(
        StatusCodes.CREATED,
        {
          id: user._id,
          fullName: user.fullName,
          userName: user.userName,
          email: user.email,
          avatar: user.avatar,
          role: user.role,
          token: {
            accessToken,
            refreshToken,
          },
        },
        "User registered successfully."
      ).send(res);
    } catch (error) {
      await User.findByIdAndDelete(user?._id);
      await deleteFileToCloudinary(user?.avatar?.publicId);
      logger.error(error);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Error during token generation. User not created."
      );
    }
  }),

  loginUser: asyncHandler(async (req, res) => {
    const { userName, phone, email, password } = req.body;

    if (!password || !(userName && phone && email)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password and one identifier required"
      );
    }

    const user = await User.findOne({
      $or: [{ email }, { userName }, { phone }],
    })
      .select("+password +token")
      .lean();

    if (!user)
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials");

    const isValid = await user.comparePassword(password);

    if (!isValid) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials.");
    }

    try {
      const { accessToken, refreshToken } = await User.generateToken(user._id);

      // Set cookies for tokens
      res
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options);

      return new ApiResponse(
        StatusCodes.OK,
        {
          id: user._id,
          fullName: user.fullName,
          userName: user.userName,
          email: user.email,
          avatar: user.avatar,
          role: user.role,
          token: {
            accessToken,
            refreshToken,
          },
        },
        "Login successful."
      ).send(res);
    } catch (error) {
      logger.error(error);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Error during token generation. Please try again later."
      );
    }
  }),

  forgotUserPassword: asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Validate email input
    if (!email) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Please provide an email address."
      );
    }

    // Find user by email
    const user = await User.findOne({ email }).lean();

    if (!user) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "User with this email does not exist."
      );
    }

    const resetToken = await user.generateCryptoToken();
    const resetTokenExpiration = expireTime;

    user.passwordResetToken = resetToken;
    user.passwordResetTokenExpiration = resetTokenExpiration;
    await user.save({ validateBeforeSave: false });

    const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;

    try {
      await sendEmail({
        to: user.email,
        subject: "Password Reset Request",
        template: "forgotPassword",
        context: {
          userName: user.fullName,
          resetUrl: resetUrl,
          expiresIn: resetTokenExpiration,
          currentYear: new Date().getFullYear(),
        },
      });
    } catch (error) {
      logger.error(error);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to send reset email. Please try again later."
      );
    }

    return new ApiResponse(
      StatusCodes.OK,
      "Password reset link has been sent to your email."
    ).send(res);
  }),

  resetUserPassword: asyncHandler(async (req, res) => {
    const { token, oldPassword, newPassword } = req.body;

    if (!token || !newPassword) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Please provide a reset token and a new password."
      );
    }

    if (oldPassword === newPassword) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "New password must be different from old password."
      );
    }

    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetTokenExpiration: { $gt: Date.now() },
    }).lean();

    if (!user) {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Invalid or expired password reset token."
      );
    }

    const isValid = await user.comparePassword(oldPassword);

    if (!isValid) {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Old password is incorrect."
      );
    }

    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiration = undefined;

    await user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      "Your password has been successfully reset."
    ).send(res);
  }),

  logoutUser: asyncHandler(async (req, res) => {
    const refreshToken = req?.cookies?.refreshToken;

    if (!refreshToken) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Refresh token required");
    }

    try {
      const decoded = jwt.verify(refreshToken, refreshTokenSecret);
    } catch (error) {
      logger.error(`Logout error: ${error.message}`);
    }

    res
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options);

    return new ApiResponse(
      StatusCodes.OK,
      "Session terminated successfully"
    ).send(res);
  }),

  refreshUserToken: asyncHandler(async (req, res) => {
    const incomingRefreshToken =
      req.cookies?.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized request");
    }

    let decoded;
    try {
      decoded = jwt.verify(incomingRefreshToken, refreshTokenSecret);
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new ApiError(StatusCodes.UNAUTHORIZED, "Refresh token expired");
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid refresh token");
      }
      throw error;
      console.log(error);
    }

    const user = await User.findById(decoded._id).select("+token").lean();

    if (!user) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not found");
    }

    if (incomingRefreshToken !== user.token.refreshToken) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Stale refresh token");
    }

    try {
      const { accessToken, refreshToken } = await User.generateToken(user._id);

      res
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options);

      return new ApiResponse(
        StatusCodes.OK,
        {
          token: {
            accessToken,
            refreshToken,
          },
        },
        "Refresh Token successful."
      ).send(res);
    } catch (error) {
      logger.error(error);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Error during token generation. Please try again later."
      );
    }
  }),
};

export default AuthController;
