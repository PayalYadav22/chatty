// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import axios from "axios";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import QRCode from "qrcode";
import speakeasy from "speakeasy";
import mongooseDelete from "mongoose-delete";
import mongooseHidden from "mongoose-hidden";
import { StatusCodes } from "http-status-codes";
import uniqueValidator from "mongoose-unique-validator";

// ==============================
// Model
// ==============================
import Session from "./session.model.js";
import TokenBlacklist from "./tokenBlacklist.model.js";

// ==============================
// Utils
// ==============================
import ApiError from "../utils/apiError.js";

// ==============================
// Constants
// ==============================
import {
  salt,
  lockTime,
  GoggleSecretKey,
  accessTokenSecret,
  refreshTokenSecret,
  accessTokenExpiresIn,
  refreshTokenExpiresIn,
  otpExpiresInMs,
  accessTokenTTL,
  maxLoginAttempt,
  refreshTokenTTL,
  tokenGracePeriod,
  passwordResetTokenTTL,
} from "../constants/constant.js";
import logger from "../logger/logger.js";

// ==============================
// Token Schema
// ==============================
const TokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    token: { type: String, required: true },
    tokenHash: { type: String, select: false },
    type: { type: String, enum: ["access", "refresh"], required: true },
    expiresAt: { type: Date, required: true },
    isBlacklisted: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "TokenBlacklist",
      default: null,
    },
    revoked: { type: Boolean, default: false },
    userAgent: { type: String },
    ipAddress: { type: String },
    location: { type: String },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  },
  { timestamps: true }
);

TokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
TokenSchema.index({ userId: 1, type: 1 });

TokenSchema.pre("save", async function (next) {
  if (this.isNew && this.type === "refresh") {
    await mongoose
      .model("Token")
      .deleteMany({ userId: this.userId, type: "refresh" });
  }
  next();
});

TokenSchema.path("expiresAt").validate(
  (value) => value > new Date(),
  "expiresAt must be a future date"
);

export const Token = mongoose.model("Token", TokenSchema);

// ==============================
// User Schema
// ==============================
const UserSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 100,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      match: [/\S+@\S+\.\S+/, "Invalid email address"],
    },
    userName: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 30,
    },
    phone: {
      type: String,
      required: true,
      trim: true,
      match: [/^\d{10}$/, "Invalid 10-digit phone number"],
    },
    password: {
      type: String,
      required: true,
      trim: true,
      minlength: 8,
      maxlength: 100,
      select: false,
      match: [
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/,
        "Password must be strong (uppercase, lowercase, number, special char)",
      ],
    },
    passwordChangedAt: Date,
    passwordResetToken: {
      type: String,
      validate: {
        validator: (v) => !v || v.length === 64,
        message: "Invalid token format.",
      },
    },
    passwordResetTokenExpiration: {
      type: Date,
      default: () => new Date(Date.now() + passwordResetTokenTTL),
      validate: {
        validator: (v) => !v || v > new Date(),
        message: "Token expired.",
      },
    },
    passwordHistory: {
      type: [String],
      default: [],
      select: false,
      validate: {
        validator: (arr) => arr.length <= 5,
        message: "Password history exceeds limit.",
      },
    },
    otp: { type: String, select: false },
    otpExpiry: {
      type: Date,
      default: () => new Date(Date.now() + otpExpiresInMs),
      select: false,
    },
    otpAttempts: { type: Number, select: false },
    avatar: {
      url: {
        type: String,
        validate: {
          validator: (v) =>
            !v || /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(v),
          message: "Invalid avatar URL.",
        },
      },
      publicId: String,
    },
    role: {
      type: String,
      enum: ["user", "admin", "superAdmin"],
      default: "user",
    },
    isVerified: { type: Boolean, default: false },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String, select: false },
    qrCode: { type: String, select: false },
    securityQuestions: [
      {
        question: String,
        answer: String,
      },
    ],
    token: { type: mongoose.Types.ObjectId, ref: "Token" },
    session: { type: mongoose.Types.ObjectId, ref: "Session" },
    tokenExpirationTime: {
      type: Date,
      default: null,
    },
    tokenVersion: { type: Number, default: 0 },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform(doc, ret) {
        ret.id = ret._id.toString();
        delete ret._id;
        delete ret.__v;
        delete ret.password;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        delete ret.passwordResetToken;
        delete ret.passwordResetTokenExpiration;
        return ret;
      },
    },
  }
);

// ==============================
// Indexes
// ==============================
UserSchema.index({ email: 1 });
UserSchema.index({ userName: 1 });
UserSchema.index({ phone: 1 });

// ==============================
// Virtuals
// ==============================
UserSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// ==============================
// Plugins
// ==============================
UserSchema.plugin(mongooseDelete, { deletedAt: true, overrideMethods: "all" });
UserSchema.plugin(mongooseHidden, {
  hidden: [
    "password",
    "otp",
    "twoFactorSecret",
    "qrCode",
    "loginAttempts",
    "lockUntil",
    "passwordResetToken",
    "passwordResetTokenExpiration",
  ],
});
UserSchema.plugin(uniqueValidator, { message: "{PATH} already exists." });

// ==============================
// Pre-save
// ==============================
UserSchema.pre("save", async function (next) {
  try {
    if (this.isModified("password")) {
      if (this.passwordHistory?.length > 0) {
        const reused = await Promise.all(
          this.passwordHistory.map((old) => bcrypt.compare(this.password, old))
        );
        if (reused.includes(true)) {
          return next(
            new ApiError(StatusCodes.BAD_REQUEST, "Password was used recently.")
          );
        }
      }
      const saltRound = await bcrypt.genSalt(salt);
      const hashed = await bcrypt.hash(this.password, saltRound);
      this.password = hashed;
      this.passwordChangedAt = new Date();
      this.passwordHistory = [
        this.password,
        ...(this.passwordHistory || []),
      ].slice(0, 5);
    }
    if (this.isModified("otp") && this.otp) {
      if (this.otpAttempts >= 5) {
        throw new ApiError(
          StatusCodes.TOO_MANY_REQUESTS,
          "Too many OTP attempts"
        );
      }
      this.otp = await bcrypt.hash(this.otp, await bcrypt.genSalt(salt));
      this.otpExpiry = new Date(Date.now() + otpExpiresInMs);
    }
    if (
      this.isModified("securityQuestions") &&
      this.securityQuestions?.length
    ) {
      const saltRound = await bcrypt.genSalt(salt);

      this.securityQuestions = await Promise.all(
        this.securityQuestions.map(async (question) => {
          const hashedAnswer = await bcrypt.hash(question.answer, saltRound);
          return { ...question, answer: hashedAnswer };
        })
      );
    }
    next();
  } catch (err) {
    next(err);
  }
});

// ==============================
// Instance Methods
// ==============================
UserSchema.methods.comparePassword = async function (password) {
  return bcrypt.compare(password, this.password);
};

UserSchema.methods.compareOTP = async function (otp) {
  return bcrypt.compare(otp, this.otp);
};

UserSchema.methods.compareSecurityAnswer = async function (
  questionId,
  providedAnswer
) {
  const question = this.securityQuestions.find(
    (q) => q._id.toString() === questionId.toString()
  );
  if (!question) {
    throw new ApiError(StatusCodes.NOT_FOUND, "Security question not found.");
  }
  return await bcrypt.compare(providedAnswer, question.answer);
};

UserSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      id: this._id,
      fullName: this.fullName,
      email: this.email,
      userName: this.userName,
      phone: this.phone,
      role: this.role,
      tokenVersion: this.tokenVersion,
    },
    accessTokenSecret,
    {
      expiresIn: accessTokenExpiresIn,
      issuer: "lets-talk",
      audience: this._id.toString(),
    }
  );
};

UserSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      id: this._id,
      fullName: this.fullName,
      email: this.email,
      userName: this.userName,
      phone: this.phone,
      role: this.role,
      tokenVersion: this.tokenVersion,
    },
    refreshTokenSecret,
    {
      expiresIn: refreshTokenExpiresIn,
      issuer: "lets-talk",
      audience: this._id.toString(),
    }
  );
};

UserSchema.methods.generateCryptoToken = function () {
  return crypto.randomBytes(32).toString("hex");
};

UserSchema.methods.hashSessionToken = function (token) {
  return crypto.createHash("sha256").update(token).digest("hex");
};

UserSchema.methods.enableTwoFactor = async function () {
  // Generate TOTP secret
  const secret = speakeasy.generateSecret({
    name: `Let's Talk - ${this.email}`,
    length: 32,
  });

  // Store secret but don't enable 2FA yet
  this.twoFactorSecret = secret.base32;
  this.twoFactorEnabled = false;

  // Generate QR Code from otpauth URL
  const qrCodeDataURL = await QRCode.toDataURL(secret.otpauth_url);

  // Save user without triggering validation
  await this.save({ validateBeforeSave: false });

  return {
    qrCodeDataURL,
  };
};

UserSchema.methods.verifyAndEnableTwoFactor = async function (id, token) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
  }

  const user = await User.findById(id).select("+twoFactorSecret");

  if (!user || !user.twoFactorSecret) {
    throw new ApiError(StatusCodes.BAD_REQUEST, "2FA setup not initiated");
  }

  const verified = speakeasy.totp.verify({
    secret: this.twoFactorSecret,
    encoding: "base32",
    token,
    window: 1,
  });

  if (!verified) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid verification code");
  }

  user.twoFactorEnabled = true;
  this.qrCode = undefined;
  await this.save({ validateBeforeSave: false });
  return { success: true };
};

UserSchema.methods.incLoginAttempts = async function () {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.loginAttempts = 1;
    this.lockUntil = undefined;
  } else {
    this.loginAttempts += 1;
    if (this.loginAttempts >= maxLoginAttempt && !this.isLocked) {
      this.lockUntil = Date.now() + lockTime;
    }
  }
  await this.save({ validateBeforeSave: false });
};

UserSchema.methods.resetLoginAttempts = async function () {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  await this.save({ validateBeforeSave: false });
};

UserSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

UserSchema.methods.isPasswordInHistory = async function (newPassword) {
  const reused = await Promise.all(
    this.passwordHistory.map((oldHash) => bcrypt.compare(newPassword, oldHash))
  );
  return reused.includes(true); // Return true if password matches any history
};

UserSchema.methods.revokeTokens = async function () {
  await Token.deleteMany({ userId: this._id });
  await TokenBlacklist.deleteMany({ userId: this._id });
};

UserSchema.methods.isTokenExpiredGracefully = function (expirationTime) {
  if (!expirationTime) return false;
  const now = new Date();
  const tokenExpiration = new Date(expirationTime);
  const gracePeriod = 5 * 60 * 1000;
  return (
    now > tokenExpiration &&
    now < new Date(tokenExpiration.getTime() + gracePeriod)
  );
};

UserSchema.methods.resetOtpAttempts = async function () {
  this.otpAttempts = 0;
  await this.save({ validateBeforeSave: false });
};

// ==============================
// Instance Statics
// ==============================
UserSchema.statics.generateToken = async function (id) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user ID.");
  }

  const user = await this.findById(id);
  if (!user) {
    throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
  }

  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  const now = Date.now();

  const accessTokenExpiresAt = new Date(now + accessTokenTTL);
  const refreshTokenExpiresAt = new Date(now + refreshTokenTTL);

  const hashToken = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  await Token.create([
    {
      userId: user._id,
      token: accessToken,
      type: "access",
      expiresAt: accessTokenExpiresAt,
    },
    {
      userId: user._id,
      token: hashToken,
      tokenHash: hashToken,
      type: "refresh",
      expiresAt: refreshTokenExpiresAt,
    },
  ]);

  return { accessToken, refreshToken };
};

UserSchema.statics.rotateTokens = async function (token, req) {
  const decoded = jwt.verify(token, refreshTokenSecret);
  const user = await this.findById(decoded.id);

  if (!user) {
    throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
  }

  // Generate new tokens
  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken(req);

  const now = Date.now();
  const accessTokenExpiresAt = new Date(now + accessTokenTTL);
  const refreshTokenExpiresAt = new Date(now + refreshTokenTTL);

  // Hash the new refresh token and store it
  const hashToken = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  // Invalidate old refresh token
  await Token.deleteOne({
    userId: user._id,
    tokenHash: crypto.createHash("sha256").update(refreshToken).digest("hex"),
  });

  // Store new access and refresh tokens
  await Token.create([
    {
      userId: user._id,
      token: accessToken,
      type: "access",
      expiresAt: accessTokenExpiresAt,
    },
    {
      userId: user._id,
      token: hashToken,
      tokenHash: hashToken,
      type: "refresh",
      expiresAt: refreshTokenExpiresAt,
    },
  ]);

  return { accessToken, refreshToken };
};

UserSchema.statics.verifyRecaptcha = async function (recaptchaToken) {
  const secretKey = GoggleSecretKey;
  const url = `https://www.google.com/recaptcha/api/siteverify`;

  try {
    const response = await axios.post(url, null, {
      params: {
        secret: secretKey,
        response: recaptchaToken,
      },
    });

    return response.data;
  } catch (error) {
    logger.error("ReCAPTCHA verification error:", error);
    throw new ApiError(StatusCodes.INTERNAL_SERVER_ERROR, error);
  }
};

// ==============================
// Export
// ==============================
const User = mongoose.model("User", UserSchema);

export default User;
