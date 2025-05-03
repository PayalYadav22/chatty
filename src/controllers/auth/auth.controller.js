// ==============================
// External Packages
// ==============================
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// ==============================
// Models
// ==============================
import User from "../../models/user.model.js";
import Session from "../../models/session.model.js";
import { TokenBlacklist } from "../../models/user.model.js";

// ==============================
// Middleware
// ==============================
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import createAuditLog from "../../middleware/auditLogger.middleware.js";
import logLoginAttempt from "../../middleware/loginLogger.middleware.js";
import createSession from "../../middleware/createSession.middleware.js";

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
  clientUrl,
  expireTime,
  sessionExpiry,
  otpExpiresInMs,
  refreshTokenSecret,
} from "../../constants/constant.js";

// ==============================
// Logger
// ==============================
import logger from "../../logger/logger.js";
import { validate } from "moongose/models/user_model.js";

const AuthController = {
  // ==============================
  // Authentication Controller
  // ==============================
  registerUser: asyncHandler(async (req, res) => {
    // Extracting required fields from the request body
    const {
      fullName,
      email,
      phone,
      userName,
      password,
      recaptchaToken,
      securityQuestions,
    } = req.body;

    // Step 1: Validate required fields (Full Name, Email, Phone, Username, Password)
    if (
      [fullName, email, phone, userName, password, securityQuestions].some(
        (f) => !f
      )
    ) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "REGISTER_FAILED",
        description:
          "Registration failed: Required registration fields are missing.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Registration failed: Please provide all the required fields (Full Name, Email, Phone, Username, Password).`
      );
    }

    // Step 2: Validate reCAPTCHA token
    if (!recaptchaToken) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "REGISTER_FAILED",
        description: "Registration failed: Missing reCAPTCHA token.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: The reCAPTCHA token is missing. Please complete the security verification to proceed with registration."
      );
    }

    // Step 3: Validate avatar file (ensure avatar image is uploaded)
    const avatarPath = req?.file?.path;
    if (!avatarPath) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "REGISTER_FAILED",
        description: "Registration failed: Missing avatar image.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: Avatar image is required. Please upload a valid avatar to complete the registration process."
      );
    }

    // Step 4: Upload avatar image to Cloudinary
    const avatar = await uploadFileToCloudinary(avatarPath);

    // Check if avatar upload was successful
    if (!avatar) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "REGISTER_FAILED",
        description:
          "Registration failed: Avatar upload failed during registration.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: Avatar upload failed. Please try again later or use a different image format."
      );
    }

    // Step 5: Check if user already exists (based on email or phone)
    const existingUser = await User.findOne({
      $or: [{ email }, { phone }],
    });

    // If the user already exists, log and throw an error
    if (existingUser) {
      await createAuditLog({
        actorId: null,
        targetId: existingUser._id,
        targetModel: "User",
        eventType: "REGISTER_FAILED",
        description:
          "Registration failed: Attempted registration with an already registered email, username, or phone number.",
        req,
      });
      throw new ApiError(
        StatusCodes.CONFLICT,
        "Registration failed: The email, username, or phone number you provided is already in use. Please use a different one."
      );
    }

    // Step 6: Generate OTP and set expiry time for OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + otpExpiresInMs);

    // Step 7: Verify reCAPTCHA token
    const recaptchaResponse = await User.verifyRecaptcha(recaptchaToken);

    // If reCAPTCHA verification fails, log and throw an error
    if (!recaptchaResponse?.success) {
      await createAuditLog({
        actorId: null,
        targetId: existingUser?._id || null,
        targetModel: "User",
        eventType: "REGISTER_FAILED",
        description:
          "Registration failed: Invalid or failed reCAPTCHA verification during registration.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Registration failed: The reCAPTCHA response is invalid. Please try again."
      );
    }

    // Step 8: Create a new user in the database
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
      securityQuestions: securityQuestions,
    });

    // Step 9: Reset OTP attempts for the new user
    await user.resetOtpAttempts();

    try {
      // Step 10: Send OTP email for email verification
      await sendEmail({
        to: user.email,
        subject: "Email Verification",
        template: "emailVerification",
        context: { name: user.fullName, otp, expiresIn: expireTime },
      });

      // Step 11: Create a successful registration audit log
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "REGISTER_SUCCESS",
        description:
          "Registration  successful: User successfully completed the registration process. Please verify your email.",
        req,
      });

      // Step 12: Return success response with user details
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
        "Registration successful: User successfully completed the registration process. Please verify your email."
      ).send(res);
    } catch (error) {
      // If an error occurs during email sending, clean up and handle errors
      await User.findByIdAndDelete(user._id);
      await deleteFileToCloudinary(avatar.publicId);
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "REGISTER_FAILED",
        description:
          "Registration failed: due to an error during the email verification process. Please try again later.",
        req,
      });

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
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description: "Login attempt failed: Missing credentials.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Login attempt failed: Missing credentials."
      );
    }

    // Step 2: Find user by email or phone
    const user = await User.findOne({ $or: [{ email }, { phone }] }).select(
      "+password +twoFactorSecret"
    );

    // Step 3: Handle user not found
    if (!user) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description: `Login attempt failed: User not found for email: ${req.body.email}`,
        req,
      });

      await logLoginAttempt({
        user: null,
        email: req.body.email,
        success: false,
        reason: "User not found",
        req,
      });

      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Authentication failed: User not found."
      );
    }

    // Step 4: Check if token is expired within a grace period
    const isTokenExpiredGracefully = user.isTokenExpiredGracefully(
      user.tokenExpirationTime
    );

    if (isTokenExpiredGracefully) {
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description:
          "Login attempt failed: Token expired but within grace period, login attempt denied.",
        req,
      });

      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Login attempt failed: Token expired but within the grace period. Please request a new token."
      );
    }

    // Step 5: Verify password
    const isValid = await user.comparePassword(password);

    if (!isValid) {
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description: "Login attempt failed: Invalid password.",
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

      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description: `Login attempt failed: Account locked. Try again in ${adjustedMinutes} ${
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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description: "Login attempt failed: Email address not verified.",
        req,
      });

      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Login failed: Your email address is not verified. Please verify your email to continue."
      );
    }

    // Step 8: Reset login attempts after successful password validation
    await user.resetLoginAttempts();

    // Step 9: verify 2FA code and enable two factor
    if (!user.twoFactorEnabled) {
      if (!twoFactorCode) {
        await createAuditLog({
          actorId: user._id,
          targetId: user._id,
          targetModel: "User",
          eventType: "LOGIN_FAILED",
          description:
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
        await createAuditLog({
          actorId: user._id,
          targetId: user._id,
          targetModel: "User",
          eventType: "LOGIN_FAILED",
          description:
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
    await createSession({
      user,
      refreshToken,
      sessionExpiry,
      req,
    });

    res
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options);

    // Step 12: Log successful login
    await createAuditLog({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: "LOGIN_SUCCESS",
      description: `Login Successful: User '${user.userName}' successfully logged in.`,
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
    const { email, otp } = req.body;

    // Step 1: Validate inputs
    if (!email || !otp) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "VERIFIED_EMAIL_FAILED",
        description:
          "Email verification failed: Missing required email or OTP.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email verification failed: Please provide both your email and the OTP."
      );
    }

    // Step 2: Retrieve user by email and ensure OTP is valid and unexpired
    const user = await User.findOne({
      email: email.trim().toLowerCase(),
      otp: { $exists: true },
      otpExpiry: { $gt: Date.now() },
      isVerified: false,
    }).select("+otp +otpExpiry");

    // Step 3: Verify that user exists and OTP matches
    if (!user || !(await user.compareOTP(otp))) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "VERIFIED_EMAIL_FAILED",
        description:
          "Email verification failed: Invalid or expired OTP entered.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email verification failed: The OTP you entered is invalid or has expired. Please request a new one."
      );
    }

    // Step 4: Enable Two-Factor Authentication (2FA)
    const twoFactorSetup = await user.enableTwoFactor();

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiry = undefined;

    await user.save({ validateBeforeSave: false });

    // Step 5: Generate authentication tokens
    const { accessToken, refreshToken } = await User.generateToken(user._id);

    // Step 6: Create a session record and set session cookie
    await createSession({
      user,
      refreshToken,
      sessionExpiry,
      req,
    });

    res
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options);

    // Step 7: Audit log for successful verification
    await createAuditLog({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: "VERIFIED_EMAIL_SUCCESS",
      description:
        "Email successfully verified. Two-Factor Authentication setup initiated.",
      req,
    });

    // Step 8: Respond with user details, tokens, and QR code
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
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
        description:
          "Password reset request failed: Missing email address in the request payload.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email address is required to request a password reset. Please provide a valid email."
      );
    }

    // Step 2: Check if the user exists with the provided email
    const user = await User.findOne({ email });

    // Step 3: Handle case where user is not found
    if (!user) {
      await createAuditLog({
        actorId: null,
        targetId: email,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
        description: `Password reset request failed: No user found for the email address: ${email}.`,
        req,
      });
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        `Password reset request failed: No user found associated with the provided email address.`
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
        await createAuditLog({
          actorId: null,
          targetId: null,
          targetModel: "User",
          eventType: "PASSWORD_RESET_REQUEST_FAILED",
          description: "Password reset request failed: Error saving session.",
          req,
        });
        logger.error("Session save error:", error);
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Session could not be saved."
        );
      }

      // Step 6: Log the security question prompt
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "PASSWORD_RESET_SECURITY_QUESTION_PROMPTED",
        description: `Security question prompt triggered for user: ${randomQuestion.question}`,
        req,
      });

      // Step 7: Respond with the security question and reset token
      return new ApiResponse(
        StatusCodes.OK,
        {
          securityQuestion: randomQuestion.question,
          resetToken: user.passwordResetToken, // Include reset token
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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_SUCCESS",
        description: `Password reset link successfully sent to user’s email: ${user.email}`,
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
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        `Password reset request failed: An error occurred while processing your request. Please try again later.`
      );
    }
  }),

  verifySecurityQuestion: asyncHandler(async (req, res) => {
    // Step 1: Extract required fields from request
    const { answer, resetToken } = req.body;
    const questionId = req.session.resetQuestion;

    // Step 2: Validate presence of required fields
    if (!answer || !resetToken || !questionId) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
        description:
          "Security question verification failed: Missing required fields in request payload.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Security question verification failed: Missing required fields in request payload."
      );
    }

    // Step 3: Find user by password reset token
    const user = await User.findOne({
      passwordResetToken: resetToken,
    }).select("+otp +otpExpire");

    // Step 4: If user not found, log and throw error
    if (!user) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_SECURITY_ANSWER_FAILED",
        description:
          "Security question verification failed: Invalid or expired reset token.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Security question verification failed: Invalid or expired reset token."
      );
    }

    // Step 5: Compare provided answer with stored security answer
    const securityAnswer = await user.compareSecurityAnswer(questionId, answer);

    // Step 6: If the answer doesn't match, log and throw error
    if (!securityAnswer) {
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "PASSWORD_RESET_SECURITY_ANSWER_FAILED",
        description:
          "Security question verification failed: Incorrect security answer provided.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Security question verification failed: Incorrect answer provided."
      );
    }

    // Step 7: Generate OTP and reset token for password reset
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + otpExpiresInMs);
    const passwordResetToken = await user.generateCryptoToken();
    const passwordResetTokenExpiration = new Date(Date.now() + otpExpiresInMs);

    user.otp = otp;
    user.otpExpiration = otpExpiry;
    user.passwordResetToken = passwordResetToken;
    user.passwordResetTokenExpiration = passwordResetTokenExpiration;

    await user.save({ validateBeforeSave: false });

    // Step 8: Send OTP and reset URL to user's email
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

    // Step 9: Log the successful verification and email dispatch
    await createAuditLog({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: "PASSWORD_RESET_SECURITY_ANSWER_SUCCESS",
      description:
        "Security question verification successful: I have sent you a reset Url and OTP. You can use these to reset your password.",
      req,
    });

    // Step 10: Respond with success message and reset URL
    return new ApiResponse(
      StatusCodes.OK,
      {
        resetUrl,
      },
      "Security question verification successful. I have sent you a reset Url and OTP. You can use these to reset your password."
    ).send(res);
  }),

  resetUserPasswordWithToken: asyncHandler(async (req, res) => {
    // Step 1: Extract token and new password from request parameters and body
    const { token } = req.params;
    const { newPassword } = req.body;

    // Step 2: Validate the presence of token and new password in the request
    if (!token || !newPassword) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
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
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REJECTED_DUE_TO_REUSED_PASSWORD",
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
    await createAuditLog({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: "PASSWORD_RESET_SUCCESS",
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
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
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
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
        description: "Password reset failed: Passwords do not match.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password reset failed: Passwords do not match."
      );
    }

    try {
      // Step 3: Retrieve the user based on the provided email and include OTP fields for validation
      const user = await User.findOne({ email }).select("+otp +otpExpire");

      // Step 4: Check if the user exists
      if (!user) {
        await createAuditLog({
          actorId: null,
          targetId: null,
          targetModel: "User",
          eventType: "PASSWORD_RESET_REQUEST_FAILED",
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
        await createAuditLog({
          actorId: null,
          targetId: null,
          targetModel: "User",
          eventType: "PASSWORD_RESET_REQUEST_FAILED",
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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "PASSWORD_RESET_SUCCESS",
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
    } catch (error) {
      // Step 11: Log the error details for internal tracking and debugging
      logger.error(error);

      // Step 12: Create an audit log for the failure, detailing the error
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "PASSWORD_RESET_REQUEST_FAILED",
        description: `Password reset failed: An unexpected error. Error: ${error.message}`,
        req,
      });

      // Step 13: Throw a general error message to the user
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Password reset failed: An unexpected error occurred while processing your password reset request. Please try again later or contact support."
      );
    }
  }),

  resendOTP: asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Step 1: Validate email input
    if (!email) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "OTP_RESET_REQUEST_FAILED",
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
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "OTP_RESET_REQUEST_FAILED",
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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "OTP_VERIFICATION_SKIPPED",
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

    await user.save({ validateBeforeSave: false });

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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "OTP_EMAIL_SEND_SUCCESS",
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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "OTP_EMAIL_SEND_FAILED",
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

  logoutUser: asyncHandler(async (req, res) => {
    // Step 1: Retrieve the refresh token from cookies
    const refreshToken = req.cookies?.refreshToken;

    // Step 2: Check if refresh token is provided, otherwise log failure and throw an error
    if (!refreshToken) {
      await createAuditLog({
        actorId: req.user?.id,
        targetId: req.user?.id,
        targetModel: "User",
        eventType: "LOGOUT_FAILED",
        description: "Logout attempt failed: Missing refresh token.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Logout attempt failed: Refresh token required."
      );
    }

    let decoded;
    try {
      // Step 3: Verify the refresh token and decode it to extract user information
      decoded = jwt.verify(refreshToken, refreshTokenSecret);
    } catch (error) {
      // Step 4: If the token is invalid, log failure and throw an error
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "LOGOUT_FAILED",
        description: "Logout attempt failed: Invalid refresh token.",
        req,
      });
      logger.error(error); // Log the error for further investigation
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Logout attempt failed: Invalid refresh token."
      );
    }

    // Step 5: Retrieve the user from the database using the decoded user ID from the token
    const user = await User.findById(decoded.id);
    if (!user) {
      // Step 6: If no user is found, log failure and throw an error
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "LOGOUT_FAILED",
        description: "Logout attempt failed: User not found.",
        req,
      });
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Step 7: Check if the token has expired gracefully (within grace period)
    const isGracefulExpiration = user.isTokenExpiredGracefully(
      decoded.exp * 1000
    );
    if (isGracefulExpiration) {
      // Step 8: If the token expired gracefully, log failure and throw an error
      await createAuditLog({
        actorId: decoded.id,
        targetId: decoded.id,
        targetModel: "User",
        eventType: "LOGOUT_FAILED",
        description:
          "Logout attempt failed: Token expired but within grace period.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Logout attempt failed: Token expired but within grace period."
      );
    }

    // Step 9: Revoke all tokens associated with the user
    await user.revokeTokens();

    // Step 10: Blacklist the specific refresh token with its expiration date
    await TokenBlacklist.create({
      token: refreshToken,
      expiresAt: new Date(decoded.exp * 1000),
      userId: user._id,
      reason: "User logged out",
    });

    // Step 11: Hash the refresh token to match with the stored hashed token
    const hashedToken = await user.hashSessionToken(refreshToken);

    // Step 12: Deactivate the user session by updating its status to inactive
    const session = await Session.findOneAndUpdate(
      { userId: decoded.id, refreshTokenHash: hashedToken, isActive: true },
      { isActive: false },
      { new: true }
    );

    if (!session) {
      // Step 13: If no active session is found, log failure and throw an error
      await createAuditLog({
        actorId: decoded.id,
        targetId: decoded.id,
        targetModel: "User",
        eventType: "LOGOUT_FAILED",
        description:
          "Logout attempt failed: Session not found or already inactive.",
        req,
      });
      throw new ApiError(StatusCodes.NOT_FOUND, "Session not found.");
    }

    // Step 14: Clear the cookies for both access and refresh tokens
    res.clearCookie("accessToken").clearCookie("refreshToken");

    // Step 15: Log the successful logout event
    await createAuditLog({
      actorId: decoded.id,
      targetId: decoded.id,
      targetModel: "User",
      eventType: "LOGOUT_SUCCESS",
      description: "User successfully logged out.",
      req,
    });

    // Step 16: Update user’s token version and disable 2FA (Two-Factor Authentication)
    user.tokenVersion += 1;
    user.twoFactorEnabled = false;
    await user.save({ validateBeforeSave: false });

    // Step 17: Send a successful logout response to the client
    return new ApiResponse(
      StatusCodes.OK,
      null,
      "Logged out successfully."
    ).send(res);
  }),

  refreshUserToken: asyncHandler(async (req, res) => {
    const incomingToken = req.cookies?.refreshToken || req.body.refreshToken;

    if (!incomingToken) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "REFRESH_TOKEN_FAILED",
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

    const blacklisted = await TokenBlacklist.findOne({
      tokenHash: hashedToken,
    });

    if (blacklisted) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "REFRESH_TOKEN_FAILED",
        description: "Refresh Token Failed: Token has been blacklisted.",
        req,
      });
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Refresh Token Failed: Token has been blacklisted."
      );
    }

    let tokenPair;
    try {
      tokenPair = await User.rotateTokens(incomingToken, req);
    } catch (error) {
      await createAuditLog({
        actorId: null,
        targetId: null,
        targetModel: "User",
        eventType: "REFRESH_TOKEN_FAILED",
        description: "Refresh Token Failed: Refresh token rotation failed.",
        req,
      });
      throw error;
    }

    const decoded = jwt.decode(tokenPair.refreshToken);
    const user = await User.findById(decoded.id);

    await createSession({
      user,
      refreshToken: tokenPair.refreshToken,
      sessionExpiry,
      req,
    });

    const isGracefulExpiration = user.isTokenExpiredGracefully(
      decoded.exp * 1000
    );

    if (isGracefulExpiration) {
      await createAuditLog({
        actorId: decoded.id,
        targetId: decoded.id,
        targetModel: "User",
        eventType: "REFRESH_TOKEN_FAILED",
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

    await createAuditLog({
      actorId: user._id,
      targetId: user._id,
      targetModel: "User",
      eventType: "REFRESH_TOKEN_SUCCESS",
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
    await createAuditLog({
      actorId: req.user?._id,
      targetId: req.user?._id,
      targetModel: "TokenBlacklist",
      eventType: "TOKENBLACK_LIST_READ",
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
      await createAuditLog({
        actorId: req.user?._id,
        targetId: req.user?._id,
        targetModel: "TokenBlacklist",
        eventType: "TOKENBLACK_LIST_REMOVE",
        description: "Token black list remove failed: Token was not provided",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Token black list remove failed: Token is required."
      );
    }

    // Step 3: Attempt to find and delete the token from the blacklist
    const deleted = await TokenBlacklist.findOneAndDelete({ token });

    // Step 4: If no token was found and deleted from the blacklist
    if (!deleted) {
      await createAuditLog({
        actorId: req.user?._id,
        targetId: req.user?._id,
        targetModel: "TokenBlacklist",
        eventType: "TOKENBLACK_LIST_REMOVE",
        description:
          "Token black list remove failed: Token not found in blacklist.",
        req,
      });
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Token black list remove failed: Token not found in blacklist."
      );
    }

    // Step 5: Log the successful removal of the token from the blacklist
    await createAuditLog({
      actorId: req.user?._id,
      targetId: deleted._id,
      targetModel: "TokenBlacklist",
      eventType: "TOKENBLACKLIST_DELETE",
      description: `Token removed from blacklist: ${token}`,
      req,
    });

    // Step 6: Return a success response indicating the token has been removed from the blacklist
    return new ApiResponse(
      StatusCodes.OK,
      null,
      `Token removed from blacklist: ${token}`
    ).send(res);
  }),

  getBlacklistCount: asyncHandler(async (req, res) => {
    // Step 1: Count the number of blacklisted tokens in the database
    const count = await TokenBlacklist.countDocuments();

    // Step 2: Create an audit log entry after fetching the count
    await createAuditLog({
      actorId: req.user?._id,
      targetId: req.user?._id,
      targetModel: "TokenBlacklist",
      eventType: "TOKENBLACK_LIST_READ",
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

  isTokenBlacklisted: asyncHandler(async (req, res) => {
    const { token } = req.body;

    // Step 1: Validate the token
    if (!token) {
      await createAuditLog({
        actorId: req.user?._id,
        targetId: req.user?._id,
        targetModel: "TokenBlacklist",
        eventType: "TOKENBLACK_LIST_READ",
        description: "Token black list count: Token missing in the request",
        req,
      });
      throw new ApiError(StatusCodes.BAD_REQUEST, "Token is required.");
    }

    // Step 2: Count the number of blacklisted tokens
    const count = await TokenBlacklist.countDocuments();

    // Step 3: Create an audit log after fetching the count
    await createAuditLog({
      actorId: req.user?._id,
      targetId: req.user?._id,
      targetModel: "TokenBlacklist",
      eventType: "TOKENBLACK_LIST_READ",
      description: "Token black list count: Count all blacklisted tokens",
      req,
    });

    // Step 4: Return the count as part of a standardized API response
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
      await createAuditLog({
        actorId: user._id,
        targetId: user._id,
        targetModel: "Session",
        eventType: "SESSION_CREATE",
        description: "Session creation failed: Refresh token is missing.",
        req,
      });

      // Throw validation error
      throw new ApiError(StatusCodes.BAD_REQUEST, "Refresh token is required.");
    }

    // Step 3: Create Session
    const session = await createSession({
      user,
      refreshToken,
      sessionExpiry,
      req,
    });

    // Step 4: Audit Log for Successful Session Creation
    await createAuditLog({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: "SESSION_CREATE",
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
    await createAuditLog({
      actorId: user._id,
      targetId: user._id,
      targetModel: "Session",
      eventType: "SESSION_LIST",
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
      await createAuditLog({
        actorId: user._id,
        targetId: sessionId,
        targetModel: "Session",
        eventType: "SESSION_VIEW_FAIL",
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
    await createAuditLog({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: "SESSION_VIEW",
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
      await createAuditLog({
        actorId: user._id,
        targetId: sessionId,
        targetModel: "Session",
        eventType: "SESSION_INVALIDATE_FAIL",
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
    await createAuditLog({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: "SESSION_INVALIDATE",
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
      await createAuditLog({
        actorId: user._id,
        targetId: sessionId,
        targetModel: "Session",
        eventType: "SESSION_DELETE_FAIL",
        description: `Session delete failed: Session not found or does not belong to the user.`,
        req,
      });
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Session delete failed: Session not found."
      );
    }

    // Step 4: Delete Session
    await session.remove(); // Corrected to remove the session

    // Step 5: Audit Log for Successful Deletion
    await createAuditLog({
      actorId: user._id,
      targetId: session._id,
      targetModel: "Session",
      eventType: "SESSION_DELETE",
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
    // Step 1: Extract the User from the Request
    const user = req.user;

    // Step 2: Count Active Sessions
    const sessionCount = await Session.countDocuments({
      userId: user._id,
      isValid: true,
    });

    // Step 2.1: If session count is not found (i.e., no active sessions)
    if (!sessionCount) {
      await createAuditLog({
        actorId: req.user._id,
        targetId: null,
        targetModel: "Session",
        eventType: "SESSION_COUNT_FAIL",
        description: `Session retrieve failed: ${error.message}`,
        req,
      });

      // Step 2.2: Throw an error if session retrieval fails
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Session retrieve failed: ${error.message}`
      );
    }

    // Step 3: Log success if session count retrieval is successful
    await createAuditLog({
      actorId: req.user._id,
      targetId: req.user._id,
      targetModel: "Session",
      eventType: "SESSION_COUNT_SUCCESS",
      description: `Session retrieve successful: Active session count retrieved successfully.`,
      req,
    });

    // Step 4: Respond with the Active Session Count
    return new ApiResponse(
      StatusCodes.OK,
      { sessionCount },
      "Session retrieve successful: Active session count retrieved successfully."
    ).send(res);
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
    await createAuditLog({
      actorId: user._id,
      targetId: user._id,
      targetModel: "Session",
      eventType: "LOGOUT_ALL_SESSIONS",
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
    await createAuditLog({
      actorId: req.user?._id || null,
      targetId: null,
      targetModel: "Session",
      eventType: "SESSION_INVALIDATE",
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
