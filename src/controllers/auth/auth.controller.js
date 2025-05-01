// ==============================
// External Packages
// ==============================
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

// ==============================
// Models
// ==============================
import User from "../../models/user.model.js";
import Session from "../../models/session.model.js";
import LoginAttempt from "../../models/loginAttempt.model.js";

// ==============================
// Middleware
// ==============================
import asyncHandler from "../../middleware/asyncHandler.middleware.js";

// ==============================
// Utils
// ==============================
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import generateOTP from "../../utils/otp.js";
import sendEmail from "../../utils/email.js";

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

    if ([fullName, email, phone, userName, password].some((f) => !f)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "All fields are required.");
    }

    const avatarPath = req?.file?.path;
    if (!avatarPath) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Avatar is missing.");
    }

    const avatar = await uploadFileToCloudinary(avatarPath);
    if (!avatar) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Avatar upload failed.");
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { userName }, { phone }],
    });
    if (existingUser) {
      throw new ApiError(
        StatusCodes.CONFLICT,
        "Email, username or phone already in use."
      );
    }

    const otp = generateOTP();
    const otpExpiry = expireTime;

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
      otp,
      otpExpiry,
    });

    const { qrCodeUrl, secret } = await User.generateTwoFactorAuth(user);
    user.qrCode = qrCodeUrl;
    user.twoFactorSecret = secret;
    await user.save({ validateBeforeSave: false });

    try {
      await sendEmail({
        to: user.email,
        subject: "Verify Your Email",
        template: "emailVerification",
        context: { name: user.fullName, otp, expiresIn: expireTime },
      });

      const { accessToken, refreshToken } = await User.generateToken(user._id);

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
          token: { accessToken, refreshToken },
          qrCode: user.qrCode,
        },
        "User registered with 2FA."
      ).send(res);
    } catch (error) {
      await User.findByIdAndDelete(user._id);
      await deleteFileToCloudinary(user.avatar.publicId);
      logger.error(error);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "User registration failed."
      );
    }
  }),

  verifyUser: asyncHandler(async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Email and OTP required.");
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase(),
      otp: { $exists: true },
      otpExpiry: { $gt: Date.now() },
      isVerified: false,
    }).select("+otp +otpExpiry");

    if (!user || !(await user.compareOTP(otp))) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid or expired OTP.");
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      { isVerified: true },
      "Email verified successfully."
    ).send(res);
  }),

  loginUser: asyncHandler(async (req, res) => {
    const { email, phone, password, twoFactorCode } = req.body;
    if (!password || (!email && !phone)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Missing credentials.");
    }

    const user = await User.findOne({ $or: [{ email }, { phone }] }).select(
      "+password +twoFactorSecret +twoFactorEnabled"
    );

    if (!user) {
      await LoginAttempt.create({
        user: null,
        email: req.body.email,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        success: false,
        reason: "User not found",
      });
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials.");
    }

    if (user.isLocked) {
      const minutes = Math.ceil((user.lockUntil - Date.now()) / 60000);
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        `Account locked. Try again in ${minutes} mins.`
      );
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await LoginAttempt.create({
        user: user._id,
        email: user.email,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        success: false,
        reason: "Incorrect password",
      });
      await user.incLoginAttempts();
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials.");
    }

    if (!user.isVerified) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Email not verified.");
    }

    await user.resetLoginAttempts();

    if (user.twoFactorEnabled) {
      if (!twoFactorCode) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "2FA code required.");
      }
      await user.verifyTwoFactorCode(user, twoFactorCode);
    }

    const { accessToken, refreshToken } = await User.generateToken(user._id);
    await Session.create({
      userId: user._id,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      token: accessToken,
      expiresAt: new Date(Date.now() + expireTime),
    });

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
        token: { accessToken, refreshToken },
      },
      "Login successful."
    ).send(res);
  }),

  forgotUserPassword: asyncHandler(async (req, res) => {
    const { email } = req.body;
    if (!email) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Email is required.");
    }

    const user = await User.findOne({ email });
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const resetToken = await user.generateCryptoToken();
    user.passwordResetToken = resetToken;
    user.passwordResetTokenExpiration = expireTime;
    await user.save({ validateBeforeSave: false });

    const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;

    await sendEmail({
      to: user.email,
      subject: "Password Reset",
      template: "forgotPassword",
      context: {
        userName: user.fullName,
        resetUrl,
        expiresIn: expireTime,
        currentYear: new Date().getFullYear(),
      },
    });

    return new ApiResponse(
      StatusCodes.OK,
      "Reset link sent to your email."
    ).send(res);
  }),

  resetUserPassword: asyncHandler(async (req, res) => {
    const { token, oldPassword, newPassword } = req.body;
    if (!token || !newPassword) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Missing token or password.");
    }

    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetTokenExpiration: { $gt: Date.now() },
    });
    if (!user) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid or expired token.");
    }

    const reused = await Promise.all(
      user.passwordHistory.map((oldHash) =>
        bcrypt.compare(newPassword, oldHash)
      )
    );
    if (reused.includes(true)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "New password must be different from previous ones."
      );
    }

    const validOld = await user.comparePassword(oldPassword);
    if (!validOld) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Incorrect old password.");
    }

    user.password = newPassword;
    user.passwordHistory = [...user.passwordHistory, user.password];
    if (user.passwordHistory.length > 5) {
      user.passwordHistory = user.passwordHistory.slice(-5);
    }

    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiration = undefined;
    await user.save({ validateBeforeSave: false });

    return new ApiResponse(StatusCodes.OK, "Password reset successfully.").send(
      res
    );
  }),

  logoutUser: asyncHandler(async (req, res) => {
    const refreshToken = req?.cookies?.refreshToken;
    if (!refreshToken) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Refresh token required.");
    }

    try {
      const decoded = jwt.verify(refreshToken, refreshTokenSecret);
      await Session.deleteMany({ userId: decoded._id });
    } catch (error) {
      logger.error(`Logout error: ${error.message}`);
    }

    res
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options);
    return new ApiResponse(StatusCodes.OK, "Logged out successfully.").send(
      res
    );
  }),

  refreshUserToken: asyncHandler(async (req, res) => {
    const incomingToken = req.cookies?.refreshToken || req.body.refreshToken;
    if (!incomingToken) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Missing refresh token.");
    }

    let decoded;
    try {
      decoded = jwt.verify(incomingToken, refreshTokenSecret);
    } catch (err) {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        err instanceof jwt.TokenExpiredError
          ? "Refresh token expired"
          : "Invalid refresh token"
      );
    }

    const user = await User.findById(decoded._id).select("+token");
    if (!user || incomingToken !== user.token?.refreshToken) {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Token mismatch or user not found."
      );
    }

    const { accessToken, refreshToken } = await User.generateToken(user._id);
    res
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options);

    return new ApiResponse(
      StatusCodes.OK,
      { token: { accessToken, refreshToken } },
      "Token refreshed successfully."
    ).send(res);
  }),
};

export default AuthController;
