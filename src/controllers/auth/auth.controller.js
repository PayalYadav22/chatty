// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// ==============================
// Models
// ==============================
import User from "../../models/user.model.js";
import Session from "../../models/session.model.js";
import TokenBlacklist from "../../models/tokenBlacklist.model.js";

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
import {
  logActivity,
  logAudit,
  logLoginAttempt,
  logSession,
} from "utils/logger.js";

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
  clientUrl,
  expireTime,
  sessionExpiry,
  otpExpiresInMs,
  refreshTokenSecret,
  logEvents,
} from "../../constants/constant.js";

// ==============================
// Logger
// ==============================
import logger from "../../logger/logger.js";

const AuthController = {
  // ==============================
  // Authentication Controller
  // ==============================
  registerUser: asyncHandler(async (req, res) => {
    // Step 1: Extracting required fields from the request body
    const {
      fullName,
      email,
      phone,
      userName,
      password,
      recaptchaToken,
      securityQuestions,
    } = req.body;

    // Step 2: Validate required fields (Full Name, Email, Phone, Username, Password)
    if ([fullName, email, phone, userName, password].some((f) => !f)) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REGISTER_FAILED,
        description:
          "Registration failed: Missing required registration fields.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Registration failed: Missing required registration fields.`
      );
    }

    // Step 3: Validate reCAPTCHA token presence
    if (!recaptchaToken) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REGISTER_FAILED,
        description: "Registration failed: Missing reCAPTCHA token.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: Missing reCAPTCHA token."
      );
    }

    // Step 4: Validate avatar file (ensure avatar image is uploaded)
    const avatarPath = req?.file?.path;
    if (!avatarPath) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REGISTER_FAILED,
        description: "Registration failed: Missing avatar image.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: Missing avatar image."
      );
    }

    // Step 5: Upload avatar image to Cloudinary
    const avatar = await uploadFileToCloudinary(avatarPath);
    if (!avatar) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REGISTER_FAILED,
        description: "Registration failed: Avatar upload to Cloudinary failed.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: Avatar upload to Cloudinary failed."
      );
    }

    // Step 6: Check if user already exists (based on email or phone)
    const existingUser = await User.findOne({
      $or: [{ email }, { phone }],
    });

    // Step 7: If the user already exists, log and throw an error
    if (existingUser) {
      await logAudit({
        actorId: existingUser._id,
        targetId: existingUser._id,
        targetModel: "User",
        eventType: logEvents.REGISTER_FAILED,
        description:
          "Registration failed: User with same email or phone already exists.",
        req,
      });
      throw new ApiError(
        StatusCodes.CONFLICT,
        "Registration failed: User with same email or phone already exists."
      );
    }

    // Step 8: Generate OTP and set expiry time for OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + otpExpiresInMs);

    // Step 9: Verify reCAPTCHA token with Google
    const recaptchaResponse = await User.verifyRecaptcha(recaptchaToken);

    // Step 10: If reCAPTCHA verification fails, log and throw an error
    if (!recaptchaResponse?.success) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REGISTER_FAILED,
        description: "Registration failed: Invalid reCAPTCHA verification.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: Invalid reCAPTCHA verification."
      );
    }

    // Step 11: Create a new user in the database with the provided and generated details
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
      isVerified: false,
      twoFactorEnabled: false,
      securityQuestions: Array.isArray(securityQuestions)
        ? securityQuestions
        : [],
    });

    // Step 12: Reset OTP attempts for the new user
    await user.resetOtpAttempts();

    try {
      // Step 13: Send OTP email for email verification
      await sendEmail({
        to: user.email,
        subject: "Email Verification",
        template: "emailVerification",
        context: { name: user.fullName, otp, expiresIn: expireTime },
      });

      // Step 14: Create a successful registration audit log
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.REGISTER_SUCCESS,
        description:
          "Registration successful: User successfully completed the registration process. Please verify your email.",
        req,
      });

      // Step 15: Record an activity log entry for successful registration
      await logActivity({
        userId: user._id,
        target: user._id,
        action: logEvents.REGISTER_SUCCESS,
        description:
          "Registration successfully: User successfully completed the registration process. Please verify your email.",
        req,
      });

      // Step 16: Return success response with user details
      return new ApiResponse(
        StatusCodes.CREATED,
        {
          id: user._id,
          fullName: user.fullName,
          userName: user.userName,
          email: user.email,
          avatar: user.avatar,
          role: user.role,
        },
        "Registration successfully: User successfully completed the registration process. Please verify your email."
      ).send(res);
    } catch (error) {
      // Step 17: In case of error (e.g. email sending fails), cleanup and log failure
      await User.findByIdAndDelete(user._id);
      await deleteFileToCloudinary(avatar.publicId);
      logger.error(error);

      // Step 18: Log audit entry for email sending failure
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.REGISTER_FAILED,
        description:
          "Registration failed: Email sending failed after registration.",
        req,
      });

      // Step 19: Throw generic error to client
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Registration failed: An error occurred during the email verification process. Please try again later."
      );
    }
  }),

  loginUser: asyncHandler(async (req, res) => {
    const { email, phone, password, twoFactorCode } = req.body;

    // Step 1: Validate required credentials
    if (!password || !twoFactorCode || (!email && !phone)) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Missing credentials.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Missing credentials.",
        req,
      });
      await logLoginAttempt({
        user: null,
        email: null,
        success: false,
        reason: `Login attempt failed: Missing credentials.`,
        req,
      });
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Login attempt failed: Missing credentials."
      );
    }

    // Step 2: Find user by email or phone
    const user = await User.findOne({ $or: [{ email }, { phone }] }).select(
      "+password +twoFactorSecret"
    );
    // Step 3: Handle user not found
    if (!user) {
      // Log failed login due to user not found
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: `Login attempt failed: User not found for email: ${req.body.email}`,
        req,
      });

      await logActivity({
        userId: null,
        action: logEvents.LOGIN_FAILED,
        description: `Login attempt failed: User not found for email: ${req.body.email}`,
        req,
      });

      await logLoginAttempt({
        user: null,
        email: req.body.email,
        success: false,
        reason: `Login attempt failed: User not found for email: ${req.body.email}`,
        req,
      });

      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        `Login attempt failed: User not found for email: ${req.body.email}`
      );
    }

    // Step 4: Check if token is expired within a grace period
    const isTokenExpiredGracefully = user.isTokenExpiredGracefully(
      user.tokenExpirationTime
    );

    if (isTokenExpiredGracefully) {
      // Log failed login due to token expired (within grace)
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description:
          "Login attempt failed: Token expired but within grace period, login attempt denied.",
        req,
      });
      await logActivity({
        userId: user._id,
        action: "LOGIN_FAILED",
        description:
          "Login attempt failed: Token expired but within grace period, login attempt denied.",
        req,
      });
      await logLoginAttempt({
        user: user._id,
        email: email,
        success: false,
        reason:
          "Login attempt failed: Token expired but within grace period, login attempt denied.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Login attempt failed: Token expired but within grace period, login attempt denied."
      );
    }

    // Step 5: Verify password
    const isValid = await user.comparePassword(password);

    if (!isValid) {
      // Log failed login due to invalid password
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Invalid password.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Invalid password.",
        req,
      });

      await logLoginAttempt({
        user: user._id,
        email: email,
        success: false,
        reason: "Login attempt failed: Invalid password.",
        req,
      });

      await user.incLoginAttempts();

      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Login attempt failed: Authentication failed."
      );
    }

    // Step 6: Check if account is locked
    if (user.isLocked) {
      const lockDurationInMillis = user.lockUntil - Date.now();
      const minutes = Math.ceil(lockDurationInMillis / 60000);
      const adjustedMinutes = minutes > 0 ? minutes : 0;

      // Log failed login due to account lock
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: `Login attempt failed: Account locked. Try again in ${adjustedMinutes} ${
          adjustedMinutes === 1 ? "minute" : "minutes"
        }.`,
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.LOGIN_FAILED,
        description: `Login attempt failed: Account locked. Try again in ${adjustedMinutes} ${
          adjustedMinutes === 1 ? "minute" : "minutes"
        }.`,
        req,
      });

      await logLoginAttempt({
        user: user._id,
        email: email,
        success: false,
        reason: `Login attempt failed: Account locked. Try again in ${adjustedMinutes} ${
          adjustedMinutes === 1 ? "minute" : "minutes"
        }.`,
        req,
      });

      throw new ApiError(
        StatusCodes.FORBIDDEN,
        `Login attempt failed: Account locked. Try again in ${adjustedMinutes} ${
          adjustedMinutes === 1 ? "minute" : "minutes"
        }.`
      );
    }

    // Step 7: Check if email is verified
    if (!user.isVerified) {
      // Log failed login due to unverified email
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Email address not verified.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Email address not verified.",
        req,
      });

      await logLoginAttempt({
        user: user._id,
        email: email,
        success: false,
        reason: "Login attempt failed: Email address not verified.",
        req,
      });

      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Login attempt failed: Email address not verified."
      );
    }

    // Step 8: Reset login attempts after successful password validation
    await user.resetLoginAttempts();

    // Step 9: Verify 2FA code and enable 2FA if not already enabled
    if (!user.twoFactorEnabled) {
      if (!twoFactorCode) {
        // Log failed login due to missing 2FA code
        await logAudit({
          actorId: user._id,
          targetId: user._id,
          targetModel: "User",
          eventType: logEvents.LOGIN_FAILED,
          description:
            "Login attempt failed: Two-Factor Authentication (2FA) code missing during login attempt.",
          req,
        });

        await logActivity({
          userId: user._id,
          action: logEvents.LOGIN_FAILED,
          description:
            "Login attempt failed: Two-Factor Authentication (2FA) code missing during login attempt.",
          req,
        });

        await logLoginAttempt({
          user: user._id,
          email: email,
          success: false,
          reason:
            "Login attempt failed: Two-Factor Authentication (2FA) code missing during login attempt.",
          req,
        });

        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Login attempt failed: Two-Factor Authentication (2FA) code is required to log in."
        );
      }

      const isValid2FA = await user.verifyAndEnableTwoFactor(
        user._id,
        twoFactorCode
      );

      if (!isValid2FA) {
        // Log failed login due to invalid 2FA code
        await logAudit({
          actorId: user._id,
          targetId: user._id,
          targetModel: "User",
          eventType: logEvents.LOGIN_FAILED,
          description:
            "Login attempt failed: Invalid 2FA code provided during login.",
          req,
        });

        await logActivity({
          userId: user._id,
          action: logEvents.LOGIN_FAILED,
          description:
            "Login attempt failed: Invalid 2FA code provided during login.",
          req,
        });

        await logLoginAttempt({
          user: user._id,
          email: email,
          success: false,
          reason:
            "Login attempt failed: Invalid 2FA code provided during login.",
          req,
        });

        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          "Login attempt failed: Invalid 2FA code. Please check your authenticator app and try again."
        );
      }
    }

    // Step 10: Generate access and refresh tokens
    const { accessToken, refreshToken } = await User.generateToken(user._id);

    // Step 11: Create session and set tokens in cookies
    await logSession({
      user,
      refreshToken,
      sessionExpiry,
      req,
    });

    res
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options);

    // Step 12: Log successful login
    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: logEvents.LOGIN_SUCCESS,
      description: `Login Successful: User '${user.userName}' successfully logged in.`,
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.LOGIN_SUCCESS,
      description: `Login Successful: User '${user.userName}' successfully logged in.`,
      req,
    });

    await logLoginAttempt({
      user: user._id,
      email: email,
      success: true,
      reason: `Login Successful: User '${user.userName}' successfully logged in.`,
      req,
    });

    // Step 13: Send successful response
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
      `Login Successful: Welcome back, ${user.fullName}! Login was successful.`
    ).send(res);
  }),

  verifyUser: asyncHandler(async (req, res) => {
    // Step 1: Extract email and OTP from the request body
    const { email, otp } = req.body;

    // Step 2: Validate required inputs (email and OTP)
    if (!email || !otp) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.VERIFIED_EMAIL_FAILED,
        description:
          "Email verification failed: Please provide both your email and the OTP.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.VERIFIED_EMAIL_FAILED,
        description:
          "Email verification failed: Please provide both your email and the OTP.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email verification failed: Please provide both your email and the OTP."
      );
    }

    // Step 3: Retrieve the user and ensure OTP is valid and not expired
    const user = await User.findOne({
      email: email.trim().toLowerCase(),
      otp: { $exists: true },
      otpExpiry: { $gt: Date.now() },
      isVerified: false,
    }).select("+otp +otpExpiry");

    // Step 4: Validate that user exists and OTP matches
    if (!user) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.VERIFIED_EMAIL_FAILED,
        description: "Email verification failed: User not found.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.VERIFIED_EMAIL_FAILED,
        description: "Email verification failed: User not found.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email verification failed: User not found."
      );
    }

    // Step 5: Check if user is already verified
    if (user.isVerified) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.VERIFIED_EMAIL_FAILED,
        description: "Email verification failed: User is already verified.",
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.VERIFIED_EMAIL_FAILED,
        description: "Email verification failed: User is already verified.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email verification failed: User is already verified."
      );
    }

    // Step 6: Compare the provided OTP with the user's saved OTP
    const isValid = await user.compareOTP(otp);
    if (!isValid) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.VERIFIED_EMAIL_FAILED,
        description:
          "Email verification failed: The OTP you entered is invalid or has expired. Please request a new one.",
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.VERIFIED_EMAIL_FAILED,
        description:
          "Email verification failed: The OTP you entered is invalid or has expired. Please request a new one.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email verification failed: The OTP you entered is invalid or has expired. Please request a new one."
      );
    }

    // Step 7: Enable Two-Factor Authentication (2FA) and generate QR code
    let twoFactorSetup;
    try {
      twoFactorSetup = await user.enableTwoFactor();
    } catch (error) {
      logger.error(error);
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.VERIFIED_EMAIL_FAILED,
        description:
          "Email verification failed: Failed to enable Two-Factor Authentication.",
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.VERIFIED_EMAIL_FAILED,
        description:
          "Email verification failed: Failed to enable Two-Factor Authentication.",
        req,
      });
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Email verification failed: Failed to enable Two-Factor Authentication."
      );
    }

    // Step 8: Mark user as verified and clear OTP details
    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiry = undefined;

    // Step 9: Generate JWT tokens for the user
    const { accessToken, refreshToken } = await User.generateToken(user._id);

    // Step 10: Create a session and store refresh token with session expiry
    try {
      await logSession({
        user,
        refreshToken,
        sessionExpiry,
        req,
      });
    } catch (error) {
      logger.error(error);
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.VERIFIED_EMAIL_FAILED,
        description: "Email verification failed: Session creation failed.",
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.VERIFIED_EMAIL_FAILED,
        description: "Email verification failed: Session creation failed.",
        req,
      });
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Email verification failed: Session creation failed."
      );
    }

    // Step 11: Save the updated user document
    await user.save({ validateBeforeSave: false });

    // Step 12: Set cookies for access and refresh tokens
    res
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options);

    // Step 13: Log successful email verification and 2FA setup
    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: logEvents.VERIFIED_EMAIL_SUCCESS,
      description:
        "Email successfully verified. Two-Factor Authentication setup initiated.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.VERIFIED_EMAIL_SUCCESS,
      description:
        "Email successfully verified. Two-Factor Authentication setup initiated.",
      req,
    });

    // Step 14: Send response with tokens and 2FA QR code
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
        qrCode: twoFactorSetup.qrCodeDataURL,
      },
      "Email verified successfully. Please scan the QR code to complete your 2FA setup and log in."
    ).send(res);
  }),

  forgotUserPassword: asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Step 1: Validate the presence of email
    if (!email) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.FORGOT_PASSWORD_FAILED,
        description:
          "Password forgot request failed: Missing email address in the request payload.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.FORGOT_PASSWORD_FAILED,
        description:
          "Password forgot request failed: Missing email address in the request payload.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password forgot request failed: Missing email address in the request payload."
      );
    }

    // Step 2: Check if the user exists with the provided email
    const user = await User.findOne({ email });

    // Step 3: Handle case where user is not found
    if (!user) {
      await logAudit({
        actorId: null,
        targetId: email,
        targetModel: "User",
        eventType: logEvents.FORGOT_PASSWORD_FAILED,
        description: `Password forgot request failed: No user found for the email address: ${email}.`,
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.FORGOT_PASSWORD_FAILED,
        description: `Password forgot request failed: No user found for the email address: ${email}.`,
        req,
      });
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        `Password forgot request failed: No user found for the email address: ${email}.`
      );
    }

    // Step 4: Generate reset token for the user
    user.passwordResetToken = await user.generateCryptoToken();
    user.passwordResetTokenExpiration = expireTime;

    await user.save({ validateBeforeSave: false });

    // Step 5: Check if the user has security questions set up
    if (user.securityQuestions?.length) {
      const randomQuestion =
        user.securityQuestions[
          Math.floor(Math.random() * user.securityQuestions.length)
        ];

      // Step 5.1: Store the selected question in the session for later verification
      req.session.resetQuestion = randomQuestion._id;

      try {
        // Step 5.2: Save the session with the selected question
        await new Promise((resolve, reject) => {
          req.session.save((err) => {
            if (err) return reject(err);
            resolve();
          });
        });
      } catch (error) {
        // Step 5.3: Handle session saving error
        logger.error("Session save error:", error);
        await logAudit({
          actorId: null,
          targetId: null,
          targetModel: "User",
          eventType: logEvents.FORGOT_PASSWORD_FAILED,
          description: "Password forgot request failed: Error saving session.",
          req,
        });
        await logActivity({
          userId: null,
          action: logEvents.FORGOT_PASSWORD_FAILED,
          description: "Password forgot request failed: Error saving session.",
          req,
        });
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Password forgot request failed: Error saving session."
        );
      }

      // Step 6: Log the security question prompt
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_SECURITY_QUESTION_PROMPTED,
        description: `Security question prompt triggered for user: ${randomQuestion.question}`,
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.PASSWORD_RESET_SECURITY_QUESTION_PROMPTED,
        description: `Security question prompt triggered for user: ${randomQuestion.question}`,
        req,
      });

      // Step 7: Respond with the security question and reset token
      return new ApiResponse(
        StatusCodes.OK,
        {
          securityQuestion: randomQuestion.question,
          resetToken: user.passwordResetToken,
        },
        "A security question has been prompted. Please answer it to proceed with your password reset."
      ).send(res);
    }

    // Step 8: If no security questions, generate OTP and store it
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + otpExpiresInMs);
    user.otp = otp;
    user.otpExpiration = otpExpiry;

    try {
      await user.save({ validateBeforeSave: false });

      // Step 9: Send OTP and reset link directly to the user's email
      const resetUrl = `${clientUrl}/reset-password/${user.passwordResetToken}`;
      await sendEmail({
        to: user.email,
        subject: "Password Reset Request",
        template: "forgotPassword",
        context: {
          userName: user.fullName,
          resetUrl,
          otp,
          expiresIn: expireTime,
          currentYear: new Date().getFullYear(),
        },
      });

      // Step 10: Log the successful email sending for audit
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.FORGOT_PASSWORD_SUCCESS,
        description: `Password reset request successfully: Password reset link successfully sent to user’s email: ${user.email}`,
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.FORGOT_PASSWORD_SUCCESS,
        description: `Password reset request successfully: Password reset link successfully sent to user’s email: ${user.email}`,
        req,
      });

      // Step 11: Respond with a success message, including the reset link and OTP
      return new ApiResponse(
        StatusCodes.OK,
        {
          resetUrl,
        },
        "Your password reset request was successful. A reset link has been sent to your email address. Please check your inbox. To reset your password, you can either use the reset link or the OTP provided. The link will expire in a few minutes, so be sure to complete the process soon."
      ).send(res);
    } catch (error) {
      // Step 12: Handle any errors during email sending
      logger.error(error);
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.FORGOT_PASSWORD_FAILED,
        description: `Password reset request failed: An error occurred while processing your request. Please try again later.`,
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.FORGOT_PASSWORD_FAILED,
        description: `Password reset request failed: An error occurred while processing your request. Please try again later.`,
        req,
      });
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        `Password reset request failed: An error occurred while processing your request. Please try again later.`
      );
    }
  }),

  verifySecurityQuestion: asyncHandler(async (req, res) => {
    const { answer, resetToken } = req.body;
    const questionId = req.session?.resetQuestion || req.body.testQuestionId;

    if (!answer || !resetToken || !questionId) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description:
          "Missing fields in security question verification request.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description:
          "Missing fields in security question verification request.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Security question verification failed: Missing required fields in request payload."
      );
    }

    const user = await User.findOne({ passwordResetToken: resetToken }).select(
      "+otp +otpExpiration"
    );

    if (!user || user.passwordResetTokenExpiration < Date.now()) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: "Invalid or expired reset token.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: "Invalid or expired reset token.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Security question verification failed: Invalid or expired reset token."
      );
    }

    const isAnswerCorrect = await user.compareSecurityAnswer(
      questionId,
      answer
    );
    if (!isAnswerCorrect) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: "Incorrect security answer provided.",
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: "Incorrect security answer provided.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Security question verification failed: Incorrect answer provided."
      );
    }

    const otp = generateOTP();
    const otpExpiration = new Date(Date.now() + otpExpiresInMs);
    const tokenExpiration = new Date(Date.now() + otpExpiresInMs);

    let newResetToken;

    try {
      newResetToken = await user.generateCryptoToken();
    } catch (error) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description:
          "There was an issue generating the reset token. Please try again later.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description:
          "There was an issue generating the reset token. Please try again later.",
        req,
      });

      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "There was an issue generating the reset token. Please try again later."
      );
    }

    user.otp = otp;
    user.otpExpiration = otpExpiration;
    user.passwordResetToken = newResetToken;
    user.passwordResetTokenExpiration = tokenExpiration;

    try {
      await user.save({ validateBeforeSave: false });
    } catch (error) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: `There was an issue saving the user data. Please try again later.`,
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: `There was an issue saving the user data. Please try again later.`,
        req,
      });

      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "There was an issue saving the user data. Please try again later."
      );
    }

    const resetUrl = `${clientUrl}/reset-password/${user.passwordResetToken}`;
    try {
      await sendEmail({
        to: user.email,
        subject: "Password Reset Request",
        template: "forgotPassword",
        context: {
          userName: user.fullName,
          resetUrl,
          otp,
          expiresIn: expireTime,
          currentYear: new Date().getFullYear(),
        },
      });
    } catch (error) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: `Email sending failed: ${error.message}`,
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.PASSWORD_RESET_REQUEST_FAILED,
        description: `Email sending failed: ${error.message}`,
        req,
      });

      return new ApiResponse(
        StatusCodes.INTERNAL_SERVER_ERROR,
        { error: "Email sending failed." },
        "There was an issue with sending the email. Please try again later."
      ).send(res);
    }

    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: logEvents.PASSWORD_RESET_REQUEST_SUCCESS,
      description: "Reset URL and OTP sent after successful verification.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.PASSWORD_RESET_REQUEST_SUCCESS,
      description: "Reset URL and OTP sent after successful verification.",
      req,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { resetUrl },
      "Security question verification successful. I have sent you a reset URL and OTP. You can use these to reset your password."
    ).send(res);
  }),

  resetUserPasswordWithToken: asyncHandler(async (req, res) => {
    // Step 1: Extract token and new password from request parameters and body
    const { token } = req.params;
    const { newPassword } = req.body;

    // Step 2: Validate the presence of token and new password in the request
    if (!token || !newPassword) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description: "Password reset failed: Missing token or new password.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description: "Password reset failed: Missing token or new password.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password reset failed: Missing token or new password."
      );
    }

    // Step 3: Find user by password reset token and validate token expiration
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetTokenExpiration: { $gt: Date.now() },
    }).select("+password +passwordHistory");

    // Step 4: If no user is found, log the failure and throw an error
    if (!user) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description:
          "Password reset attempt failed: No user found with the provided reset token. It may be invalid or expired.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description:
          "Password reset attempt failed: No user found with the provided reset token. It may be invalid or expired.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Password reset failed: The reset token is invalid or expired. Please request a new one."
      );
    }

    // Step 5: Check if the new password has been previously used
    const isReused = await user.isPasswordInHistory(newPassword);

    // Step 6: If the password is reused, log and reject the reset attempt
    if (isReused) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description:
          "Password reset attempt rejected: The provided new password matches a previously used password.",
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description:
          "Password reset attempt rejected: The provided new password matches a previously used password.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password reset failed: Please choose a new password that has not been used previously."
      );
    }

    // Step 7: Update user's password and manage password history
    user.passwordHistory.push(user.password);
    user.password = newPassword;

    // Step 8: Ensure that password history does not exceed the limit of 5 entries
    if (user.passwordHistory.length > 5) {
      user.passwordHistory = user.passwordHistory.slice(-5);
    }

    // Step 9: Clear the reset token and expiration
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiration = undefined;

    // Step 10: Increment the token version for added security (forces re-login)
    user.tokenVersion += 1;

    // Step 11: Revoke all active tokens to force reauthentication
    await user.revokeTokens();

    // Step 12: Save the updated user data, bypassing validation if needed
    await user.save({ validateBeforeSave: false });

    // Step 13: Log the successful password reset event
    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
      description:
        "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password.",
      req,
    });
    await logActivity({
      userId: user._id,
      action: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
      description:
        "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password.",
      req,
    });

    // Step 14: Respond with a success message to inform the user
    return new ApiResponse(
      StatusCodes.OK,
      null,
      "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password."
    ).send(res);
  }),

  resetUserPasswordWithOTP: asyncHandler(async (req, res) => {
    const { email, otp, newPassword, confirmPassword } = req.body;

    // Step 1: Validate that all required fields are provided
    if ([email, otp, newPassword, confirmPassword].some((field) => !field)) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: Missing token or new password.",
        req,
      });
      await logActivity({
        userId: null,
        eventType: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: Missing token or new password.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password reset failed: Missing token or new password."
      );
    }

    // Step 2: Ensure the new password and confirm password match
    if (newPassword !== confirmPassword) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: Passwords do not match.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: Passwords do not match.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password reset failed: Passwords do not match."
      );
    }

    // Step 3: Retrieve the user based on the provided email and include OTP fields for validation
    const user = await User.findOne({ email }).select("+otp +otpExpire");

    // Step 4: Check if the user exists
    if (!user) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: User not found.",
        req,
      });
      await logAudit({
        userId: null,
        action: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: User not found.",
        req,
      });
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Password reset failed: User not found."
      );
    }

    // Step 5: Verify the OTP provided by the user
    const isValid = await user.compareOTP(otp);

    // Step 6: Check if OTP is valid or expired
    if (!isValid) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: Invalid or expired OTP.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.PASSWORD_RESET_WITH_OTP_FAILED,
        description: "Password reset failed: Invalid or expired OTP.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password reset failed: Invalid or expired OTP."
      );
    }

    // Step 7: Proceed to update the user's password and clear OTP-related fields
    user.password = newPassword;
    user.otp = undefined;
    user.otpExpiry = undefined;

    // Step 8: Save the updated user without validation
    await user.save({ validateBeforeSave: false });

    // Step 9: Log the successful password reset action
    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: logEvents.PASSWORD_RESET_WITH_OTP_SUCCESS,
      description:
        "Password Reset Successful: Your password has been successfully reset using the provided otp. You can now log in with your new password.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.PASSWORD_RESET_WITH_OTP_SUCCESS,
      description:
        "Password Reset Successful: Your password has been successfully reset using the provided otp. You can now log in with your new password.",
      req,
    });

    // Step 10: Send a success response to the user
    return new ApiResponse(
      StatusCodes.OK,
      null,
      "Password Reset Successful: Your password has been successfully reset using the provided otp. You can now log in with your new password."
    ).send(res);
  }),

  resendOTP: asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Step 1: Validate email input
    if (!email) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP reset failed: Missing email.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP reset failed: Missing email.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "OTP reset failed: Missing email."
      );
    }

    // Step 2: Find user by email
    const user = await User.findOne({ email }).select(
      "+otp +otpExpiration +otpAttempts"
    );

    // Step 3: If user not found, log audit and return generic success response
    if (!user) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP reset failed: No user found with provided email.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP reset failed: No user found with provided email.",
        req,
      });
      throw new ApiError(
        StatusCodes.OK,
        "OTP reset failed: If an account with this email exists, an OTP has been sent. Please check your inbox."
      );
    }

    // Step 4: If user is already verified, skip OTP and log audit
    if (user.isVerified) {
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP verification skipped: Email is already verified.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP verification skipped: Email is already verified.",
        req,
      });

      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "OTP verification skipped: Email is already verified."
      );
    }

    // Step 5: Generate OTP and expiration
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + otpExpiresInMs);

    // Step 6: Update user document with new OTP and reset attempts
    user.otp = otp;
    user.otpExpiry = otpExpiry;
    user.otpAttempts = 0;

    try {
      await user.save({ validateBeforeSave: false });
    } catch (error) {
      logger.error("Failed to save OTP:", error);
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: `Failed to update user with OTP: ${error.message}`,
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: `Failed to update user with OTP: ${error.message}`,
        req,
      });
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to update user with OTP. Please try again."
      );
    }

    // Step 7: Attempt to send verification email
    try {
      await sendEmail({
        to: user.email,
        subject: "Verify Your Email",
        template: "emailVerification",
        context: {
          name: user.fullName,
          otp,
          expiresIn: "10 minutes",
        },
      });

      // Step 8: Log successful OTP email send
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.OTP_RESET_REQUEST_SUCCESS,
        description:
          "OTP verification successful: Verification email with OTP sent successfully.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.OTP_RESET_REQUEST_SUCCESS,
        description:
          "OTP verification successful: Verification email with OTP sent successfully.",
        req,
      });

      // Step 9: Return success response (generic to avoid leaking user existence)
      return new ApiResponse(
        StatusCodes.OK,
        null,
        "OTP verification successful: If an account exists with this email, a new OTP has been sent for verification. Please check your inbox."
      ).send(res);
    } catch (error) {
      logger.error(error);

      // Step 10: On failure, clear OTP fields and save user
      user.otp = undefined;
      user.otpExpiry = undefined;
      await user.save({ validateBeforeSave: false });

      // Step 11: Log OTP email send failure
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: `Failed to send verification email: ${
          error.message || "Unknown error"
        }.`,
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: `Failed to send verification email: ${
          error.message || "Unknown error"
        }.`,
        req,
      });

      // Step 12: Throw internal server error
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to send verification email."
      );
    }
  }),

  logoutUser: asyncHandler(async (req, res, next) => {
    try {
      // Step 1: Get refresh token from cookies
      const refreshToken = req.cookies?.refreshToken;

      // Step 2: Validate presence of refresh token
      if (!refreshToken) {
        await logAudit({
          actorId: req.user?.id,
          targetId: req.user?.id,
          targetModel: "User",
          eventType: logEvents.LOGOUT_FAILED,
          description: "Logout attempt failed: Missing refresh token.",
          req,
        });
        await logActivity({
          userId: req.user?.id,
          action: logEvents.LOGOUT_FAILED,
          description: "Logout attempt failed: Missing refresh token.",
          req,
        });
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Logout attempt failed: Refresh token required."
        );
      }

      let decoded;
      // Step 3: Try to verify the refresh token
      try {
        decoded = jwt.verify(refreshToken, refreshTokenSecret);
      } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
          const decodedGracefully = jwt.decode(refreshToken);
          const user = await User.findById(decodedGracefully?.id);

          if (
            user &&
            user.isTokenExpiredGracefully(error.expiredAt.getTime())
          ) {
            await logAudit({
              actorId: decodedGracefully?.id || null,
              targetId: decodedGracefully?.id || null,
              targetModel: "User",
              eventType: logEvents.LOGOUT_FAILED,
              description:
                "Logout attempt failed: Token expired but within grace period.",
              req,
            });
            await logActivity({
              userId: decodedGracefully?.id || null,
              action: logEvents.LOGOUT_FAILED,
              description:
                "Logout attempt failed: Token expired but within grace period.",
              req,
            });
            throw new ApiError(
              StatusCodes.UNAUTHORIZED,
              "Logout attempt failed: Token expired but within grace period."
            );
          }
        }

        // For invalid, tampered, or other errors
        await logAudit({
          actorId: null,
          targetId: null,
          targetModel: "User",
          eventType: logEvents.LOGOUT_FAILED,
          description: "Logout attempt failed: Invalid refresh token.",
          req,
        });
        await logActivity({
          userId: null,
          action: logEvents.LOGOUT_FAILED,
          description: "Logout attempt failed: Invalid refresh token.",
          req,
        });
        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          "Logout attempt failed: Invalid refresh token."
        );
      }

      // Step 4: Find the user from decoded token
      const user = await User.findById(decoded.id);
      if (!user) {
        await logAudit({
          actorId: decoded.id,
          targetId: decoded.id,
          targetModel: "User",
          eventType: logEvents.LOGOUT_FAILED,
          description: "Logout attempt failed: User not found.",
          req,
        });
        await logActivity({
          userId: decoded.id,
          action: logEvents.LOGOUT_FAILED,
          description: "Logout attempt failed: User not found.",
          req,
        });
        throw new ApiError(
          StatusCodes.NOT_FOUND,
          "Logout attempt failed: User not found."
        );
      }

      // Step 5: Revoke active tokens and blacklist the refresh token
      await user.revokeTokens();

      const hashedToken = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");
      await TokenBlacklist.create({
        token: hashedToken,
        expiresAt: new Date(decoded.exp * 1000),
        userId: user._id,
        reason: "User logged out",
      });

      // Step 6: Hash the refresh token for session matching
      const hashedSessionToken = await user.hashSessionToken(refreshToken);

      // Step 7: Mark session as inactive
      const session = await Session.findOneAndUpdate(
        {
          userId: decoded.id,
          refreshTokenHash: hashedSessionToken,
          isActive: true,
        },
        { isActive: false },
        { new: true }
      );

      // Handle missing or already inactive session
      if (!session) {
        await logAudit({
          actorId: decoded.id,
          targetId: decoded.id,
          targetModel: "User",
          eventType: logEvents.LOGOUT_FAILED,
          description: "Session not found or already inactive.",
          req,
        });
        await logActivity({
          userId: decoded.id,
          action: logEvents.LOGOUT_FAILED,
          description: "Session not found or already inactive.",
          req,
        });
        throw new ApiError(StatusCodes.NOT_FOUND, "Session not found.");
      }

      // Step 8: Clear cookies
      res.clearCookie("accessToken").clearCookie("refreshToken");

      // Step 9: Log successful logout
      await logAudit({
        actorId: decoded.id,
        targetId: decoded.id,
        targetModel: "User",
        eventType: logEvents.LOGOUT_SUCCESS,
        description: "User successfully logged out.",
        req,
      });
      await logActivity({
        userId: decoded.id,
        action: logEvents.LOGOUT_SUCCESS,
        description: "User successfully logged out.",
        req,
      });

      // Step 10: Invalidate all future tokens and disable 2FA
      user.twoFactorEnabled = false;
      await user.save({ validateBeforeSave: false });

      // Step 11: Return success response
      return new ApiResponse(
        StatusCodes.OK,
        null,
        "Logged out successfully."
      ).send(res);
    } catch (error) {
      next(error);
    }
  }),

  refreshUserToken: asyncHandler(async (req, res) => {
    const incomingToken = req.cookies?.refreshToken || req.body.refreshToken;

    if (!incomingToken) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Missing refresh token.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Missing refresh token.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Refresh Token Failed: Missing refresh token."
      );
    }

    // Check if blacklisted (use hashed version for consistency)
    const hashedToken = crypto
      .createHash("sha256")
      .update(incomingToken)
      .digest("hex");

    let blacklisted;
    try {
      blacklisted = await TokenBlacklist.findOne({
        tokenHash: hashedToken,
      });
    } catch (error) {
      console.log("Caught error in TokenBlacklist.findOne:", error.message);
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Database error.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Database error.",
        req,
      });
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Refresh Token Failed: Database error."
      );
    }

    if (blacklisted) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Blacklisted refresh token.",
        req,
      });

      await logActivity({
        userId: null,
        action: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Blacklisted refresh token.",
        req,
      });

      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Refresh Token Failed: Blacklisted refresh token."
      );
    }

    let tokenPair;
    try {
      tokenPair = await User.rotateTokens(incomingToken, req);
    } catch (error) {
      await logAudit({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Refresh token rotation failed.",
        req,
      });
      await logActivity({
        userId: null,
        action: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Refresh token rotation failed.",
        req,
      });
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        error.message || "Refresh Token Failed: Refresh token rotation failed."
      );
    }

    const decoded = jwt.decode(tokenPair.refreshToken);
    const user = await User.findById(decoded.id);

    await logSession({
      user,
      refreshToken: tokenPair.refreshToken,
      sessionExpiry,
      req,
    });

    const isGracefulExpiration = user.isTokenExpiredGracefully(
      decoded.exp * 1000
    );

    if (isGracefulExpiration) {
      await logAudit({
        actorId: decoded.id,
        targetId: decoded.id,
        targetModel: "User",
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description:
          "Refresh Token Failed: Token expired but within grace period.",
        req,
      });
      await logActivity({
        userId: decoded.id,
        action: logEvents.REFRESH_TOKEN_FAILED,
        description:
          "Refresh Token Failed: Token expired but within grace period.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Refresh Token Failed: Token expired but within grace period."
      );
    }

    res
      .cookie("accessToken", tokenPair.accessToken, options)
      .cookie("refreshToken", tokenPair.refreshToken, options);

    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: logEvents.REFRESH_TOKEN_SUCCESS,
      description: "Refresh Token successful: Token refreshed successfully.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.REFRESH_TOKEN_SUCCESS,
      description: "Refresh Token successful: Token refreshed successfully.",
      req,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { token: tokenPair },
      "Refresh Token successful: Token refreshed successfully."
    ).send(res);
  }),

  // ==============================
  // Black List Controller
  // ==============================
  getAllBlacklistedTokens: asyncHandler(async (req, res) => {
    // STEP 1: Fetch all blacklisted tokens from the database
    const tokens = await TokenBlacklist.find()
      .populate("userId", "fullName userName email phone avatar role")
      .sort({ createdAt: -1 });

    // STEP 2: Create an audit log for monitoring and traceability
    await logAudit({
      actorId: req.user?._id,
      targetId: req.user?._id,
      targetModel: "TokenBlacklist",
      eventType: logEvents.TOKEN_BLACK_LIST_READ,
      description: "Token black list fetched: Fetched all blacklisted tokens",
      req,
    });

    await logActivity({
      userId: req.user?._id,
      action: logEvents.TOKEN_BLACK_LIST_READ,
      description: "Token black list fetched: Fetched all blacklisted tokens",
      req,
    });

    // STEP 3: Send the final response to the client
    return new ApiResponse(
      StatusCodes.OK,
      {
        count: tokens.length,
        data: tokens,
      },
      "Tokens retrieved successfully"
    ).send(res);
  }),

  removeBlacklistToken: asyncHandler(async (req, res) => {
    // Step 1: Extract the token from the request body
    const { token } = req.body;

    // Step 2: Check if the token is provided in the request body
    if (!token) {
      // Step 2.1: Log the failure due to missing token
      await logAudit({
        actorId: req.user?._id,
        targetId: req.user?._id,
        targetModel: "TokenBlacklist",
        eventType: logEvents.TOKEN_BLACK_LIST_REMOVE_FAILED,
        description: "Token black list remove failed: Token was not provided",
        req,
      });

      await logActivity({
        userId: req.user?._id,
        action: logEvents.TOKEN_BLACK_LIST_REMOVE_FAILED,
        description: "Token black list remove failed: Token was not provided",
        req,
      });

      // Step 2.2: Throw a bad request error
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Token black list remove failed: Token is required."
      );
    }

    // Step 3: Hash the token to match the stored format in the blacklist
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // Step 4: Attempt to find and delete the token from the blacklist
    const deleted = await TokenBlacklist.findOneAndDelete({
      token: hashedToken,
    });

    // Step 5: If the token was not found in the blacklist
    if (!deleted) {
      // Step 5.1: Log the failure due to token not being in blacklist
      await logAudit({
        actorId: req.user?._id,
        targetId: req.user?._id,
        targetModel: "TokenBlacklist",
        eventType: logEvents.TOKEN_BLACK_LIST_REMOVE_FAILED,
        description:
          "Token black list remove failed: Token not found in blacklist.",
        req,
      });

      await logActivity({
        userId: req.user?._id,
        action: logEvents.TOKEN_BLACK_LIST_REMOVE_FAILED,
        description:
          "Token black list remove failed: Token not found in blacklist.",
        req,
      });

      // Step 5.2: Throw a not found error
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Token black list remove failed: Token not found in blacklist."
      );
    }

    // Step 6: Log the successful removal of the token from the blacklist
    await logAudit({
      actorId: req.user?._id,
      targetId: deleted._id,
      targetModel: "TokenBlacklist",
      eventType: logEvents.TOKEN_BLACK_LIST_REMOVE_SUCCESS,
      description: `Token removed from blacklist: ${token}`,
      req,
    });

    await logAudit({
      actorId: req.user?._id,
      targetId: deleted._id,
      targetModel: "TokenBlacklist",
      eventType: logEvents.TOKEN_BLACK_LIST_REMOVE_SUCCESS,
      description: `Token removed from blacklist: ${token}`,
      req,
    });

    // Step 7: Return a success response
    return new ApiResponse(
      StatusCodes.OK,
      {
        token,
      },
      `Token removed from blacklist`
    ).send(res);
  }),

  getBlacklistCount: asyncHandler(async (req, res) => {
    // Step 1: Count the number of blacklisted tokens in the database
    const count = await TokenBlacklist.countDocuments();

    // Step 2: Create an audit log entry after fetching the count
    await logAudit({
      actorId: req.user?._id,
      targetId: req.user?._id,
      targetModel: "TokenBlacklist",
      eventType: logEvents.TOKEN_BLACK_LIST_READ,
      description: "Token black list count: Count all blacklisted tokens",
      req,
    });

    await logActivity({
      actorId: req.user?._id,
      targetId: req.user?._id,
      targetModel: "TokenBlacklist",
      eventType: logEvents.TOKEN_BLACK_LIST_READ,
      description: "Token black list count: Count all blacklisted tokens",
      req,
    });

    // Step 3: Return the count as part of a standardized API response
    return new ApiResponse(
      StatusCodes.OK,
      count,
      "Tokens count successfully"
    ).send(res);
  }),

  // ==============================
  // Session Controller
  // ==============================
  createSession: asyncHandler(async (req, res) => {
    // Step 1: Extract Authenticated User & Refresh Token
    const user = req.user;
    const { refreshToken } = req.body;

    // Step 2: Validate Refresh Token
    if (!refreshToken) {
      // Log failure due to missing refresh token
      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "Session",
        eventType: logEvents.SESSION_CREATE_FAILED,
        description: "Session creation failed: Refresh token is missing.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.SESSION_CREATE_FAILED,
        description: "Session creation failed: Refresh token is missing.",
        req,
      });

      // Throw validation error
      throw new ApiError(StatusCodes.BAD_REQUEST, "Refresh token is required.");
    }

    // Step 3: Create Session
    const session = await logSession({
      user,
      refreshToken,
      sessionExpiry,
      req,
    });

    // Step 4: Audit Log for Successful Session Creation
    await logAudit({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: logEvents.SESSION_CREATE_SUCCESS,
      description:
        "Session created successfully: New session created for user.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.SESSION_CREATE_SUCCESS,
      description:
        "Session created successfully: New session created for user.",
      req,
    });

    // Step 5: Send Success Response
    return new ApiResponse(
      StatusCodes.CREATED,
      {
        sessionId: session._id,
        deviceFingerprint: session.deviceFingerprint,
        expiresAt: session.expiresAt,
      },
      "Session created successfully: New session created for user."
    ).send(res);
  }),

  getSessionsForUser: asyncHandler(async (req, res) => {
    // Step 1: Extract Authenticated User
    const user = req.user;

    // Step 2: Fetch Active Sessions
    const sessions = await Session.find({
      userId: user._id,
      isValid: true,
      expiresAt: { $gt: new Date() },
    })
      .sort({ createdAt: -1 })
      .select("-refreshTokenHash")
      .lean();

    // Step 3: Log Session Retrieval
    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "Session",
      eventType: logEvents.SESSION_LIST,
      description: "Session list fetched: Retrieved active sessions for user.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.SESSION_LIST,
      description: "Session list fetched: Retrieved active sessions for user.",
      req,
    });

    // Step 4: Respond with Sessions
    return new ApiResponse(
      StatusCodes.OK,
      { sessions },
      "Active sessions retrieved successfully."
    ).send(res);
  }),

  getSessionById: asyncHandler(async (req, res) => {
    // Step 1: Extract User and Session ID
    const user = req.user;
    const { sessionId } = req.params;

    // Step 2: Validate Session ID
    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid session ID.");
    }

    // Step 3: Find Session Belonging to User
    const session = await Session.findOne({
      _id: sessionId,
      userId: user._id,
    })
      .select("-refreshTokenHash")
      .lean();

    // Step 4: Handle Session Not Found
    if (!session) {
      await logAudit({
        actorId: user._id,
        targetId: sessionId,
        targetModel: "Session",
        eventType: logEvents.SESSION_VIEW_FAILED,
        description:
          "Session view failed: Session not found or does not belong to the user.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.SESSION_VIEW_FAILED,
        description:
          "Session view failed: Session not found or does not belong to the user.",
        req,
      });

      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Session view failed: Session not found or does not belong to the user."
      );
    }

    // Step 5: Audit Log for Viewing Session
    await logAudit({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: logEvents.SESSION_VIEW_SUCCESS,
      description: "Session view successful: Viewed specific session by ID.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.SESSION_VIEW_SUCCESS,
      description: "Session view successful: Viewed specific session by ID.",
      req,
    });

    // Step 6: Respond with Session Details
    return new ApiResponse(
      StatusCodes.OK,
      { session },
      "Session view successful: Session details retrieved successfully."
    ).send(res);
  }),

  invalidateSession: asyncHandler(async (req, res) => {
    // Step 1: Extract User & Session ID
    const user = req.user;
    const { sessionId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid session ID.");
    }

    // Step 2: Find Session for the User
    const session = await Session.findOne({
      _id: sessionId,
      userId: user._id,
      isValid: true,
    });

    // Step 3: Handle If Session is Not Found or Already Invalid
    if (!session) {
      await logAudit({
        actorId: user._id,
        targetId: sessionId,
        targetModel: "Session",
        eventType: logEvents.SESSION_INVALIDATION_FAILED,
        description:
          "Session invalidate failed: Session not found or already invalid.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.SESSION_INVALIDATION_FAILED,
        description:
          "Session invalidate failed: Session not found or already invalid.",
        req,
      });

      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Session invalidate failed: Session not found or already invalid."
      );
    }

    // Step 4: Invalidate the Session
    session.isValid = false;
    await session.save({ validateBeforeSave: false });

    // Step 5: Audit Log for Invalidating Session
    await logAudit({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: logEvents.SESSION_INVALIDATION_SUCCESS,
      description: `Session invalidated successful: Session ID ${sessionId} marked as invalid.`,
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.SESSION_INVALIDATION_SUCCESS,
      description: `Session invalidated successful: Session ID ${sessionId} marked as invalid.`,
      req,
    });

    // Step 6: Respond with Success
    return new ApiResponse(
      StatusCodes.OK,
      {},
      "Session invalidated successfully: Session marked as invalid."
    ).send(res);
  }),

  deleteSession: asyncHandler(async (req, res) => {
    // Step 1: Extract User & Session ID
    const user = req.user;
    const { sessionId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid session Id.");
    }

    // Step 2: Find Session Belonging to User
    const session = await Session.findOne({
      _id: sessionId,
      userId: user._id,
    });

    // Step 3: Handle Session Not Found
    if (!session) {
      await logAudit({
        actorId: user._id,
        targetId: sessionId,
        targetModel: "Session",
        eventType: logEvents.SESSION_DELETE_FAILED,
        description: `Session delete failed: Session not found or does not belong to the user.`,
        req,
      });
      await logActivity({
        userId: user._id,
        action: logEvents.SESSION_DELETE_FAILED,
        description: `Session delete failed: Session not found or does not belong to the user.`,
        req,
      });
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Session delete failed: Session not found."
      );
    }

    // Step 4: Delete Session
    await Session.findByIdAndDelete(sessionId);

    // Step 5: Audit Log for Successful Deletion
    await logAudit({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: logEvents.SESSION_DELETE_SUCCESS,
      description: "Session delete successful: Session deleted successfully.",
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.SESSION_DELETE_SUCCESS,
      description: "Session delete successful: Session deleted successfully.",
      req,
    });

    // Step 6: Respond with Success
    return new ApiResponse(
      StatusCodes.OK,
      null,
      "Session deleted successfully."
    ).send(res);
  }),

  getActiveSessionCount: asyncHandler(async (req, res) => {
    try {
      const user = req.user;

      const sessionCount = await Session.countDocuments({
        userId: user._id,
        isValid: true,
      });

      await logAudit({
        actorId: user._id,
        targetId: user._id,
        targetModel: "Session",
        eventType: logEvents.SESSION_COUNT_SUCCESS,
        description:
          "Session retrieve successful: Active session count retrieved successfully.",
        req,
      });

      await logActivity({
        userId: user._id,
        action: logEvents.SESSION_COUNT_SUCCESS,
        description:
          "Session retrieve successful: Active session count retrieved successfully.",
        req,
      });

      return new ApiResponse(
        StatusCodes.OK,
        { sessionCount },
        "Session retrieve successful: Active session count retrieved successfully."
      ).send(res);
    } catch (error) {
      await logAudit({
        actorId: req.user._id,
        targetId: null,
        targetModel: "Session",
        eventType: logEvents.SESSION_COUNT_FAILED,
        description: `Session retrieve failed: ${error.message}`,
        req,
      });

      await logActivity({
        userId: req.user._id,
        action: logEvents.SESSION_COUNT_FAILED,
        description: `Session retrieve failed: ${error.message}`,
        req,
      });

      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Session retrieve failed: ${error.message}`
      );
    }
  }),

  logoutAllSessions: asyncHandler(async (req, res) => {
    // Step 1: Extract the authenticated user from the request
    const user = req.user;

    // Step 2: Invalidate all active sessions for the user by setting `isValid` to false
    await Session.updateMany(
      { userId: user._id, isValid: true },
      { $set: { isValid: false } }
    );

    // Step 3: Optionally delete all sessions from the database
    await Session.deleteMany({ userId: user._id });

    // Step 4: Log the logout event for auditing purposes
    await logAudit({
      actorId: user._id,
      targetId: user._id,
      targetModel: "Session",
      eventType: logEvents.LOGOUT_ALL_SESSIONS,
      description: `Session logout successful: All sessions for user ${user._id} have been logged out.`,
      req,
    });

    await logActivity({
      userId: user._id,
      action: logEvents.LOGOUT_ALL_SESSIONS,
      description: `Session logout successful: All sessions for user ${user._id} have been logged out.`,
      req,
    });

    // Step 5: Respond with a success message
    return new ApiResponse(
      StatusCodes.OK,
      {},
      "Session logout successful: All sessions have been logged out successfully."
    ).send(res);
  }),

  cleanupExpiredSessions: asyncHandler(async (req, res) => {
    // Step 1: Define the current timestamp
    const now = new Date();

    // Step 2: Delete sessions that are expired based on `expiresAt` field
    const result = await Session.deleteMany({
      expiresAt: { $lte: now },
    });

    // Step 3: Create an audit log for the cleanup operation
    await logAudit({
      actorId: req.user?._id || null,
      targetId: null,
      targetModel: "Session",
      eventType: logEvents.SESSION_INVALIDATION_SUCCESS,
      description: `Expired session cleanup completed successfully. ${result.deletedCount} session(s) removed.`,
      req,
    });

    await logActivity({
      userId: req.user?._id || null,
      action: logEvents.SESSION_INVALIDATION_SUCCESS,
      description: `Expired session cleanup completed successfully. ${result.deletedCount} session(s) removed.`,
      req,
    });

    // Step 4: Respond with the result
    return new ApiResponse(
      StatusCodes.OK,
      { deletedSessions: result.deletedCount },
      `Expired sessions cleaned up successfully.`
    ).send(res);
  }),
};

export default AuthController;
