// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { StatusCodes } from "http-status-codes";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import mongooseDelete from "mongoose-delete";
import mongooseHidden from "mongoose-hidden";
import uniqueValidator from "mongoose-unique-validator";

// ==============================
// Utils
// ==============================
import ApiError from "../utils/apiError.js";

// ==============================
// Constants
// ==============================
import {
  salt,
  accessTokenSecret,
  refreshTokenSecret,
  accessTokenExpiresIn,
  refreshTokenExpiresIn,
  maxLoginAttempt,
  lockTime,
} from "../constants/constant.js";

// ==============================
// Token BlackList Schema Definition
// ==============================

const TokenBlacklistSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
});

export const TokenBlacklist = mongoose.model(
  "TokenBlacklist",
  TokenBlacklistSchema
);

// ==============================
// Token Schema Definition
// ==============================
const TokenSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    token: { type: String, required: true },
    type: { type: String, enum: ["access", "refresh"], required: true },
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  { timestamps: true }
);

TokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const Token = mongoose.model("Token", TokenSchema);

// ==============================
// User Schema Definition
// ==============================
const UserSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      trim: true,
      lowercase: true,
      required: [true, "Full name is required."],
      minlength: [3, "Full name must be at least 3 characters long"],
      maxlength: [100, "Full name cannot exceed 100 characters"],
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
      required: [true, "Email is required."],
      unique: true,
      match: [/\S+@\S+\.\S+/, "Please enter a valid email address"],
    },
    userName: {
      type: String,
      trim: true,
      lowercase: true,
      required: [true, "Username is required."],
      unique: true,
      minlength: [3, "Username must be at least 3 characters long"],
      maxlength: [30, "Username cannot exceed 30 characters."],
    },
    phone: {
      type: String,
      trim: true,
      required: [true, "Phone number is required."],
      match: [/^\d{10}$/, "Please enter a valid 10-digit phone number"],
    },
    password: {
      type: String,
      trim: true,
      required: [true, "Password is required."],
      minlength: [8, "Password must be at least 8 characters long"],
      maxlength: [100, "Password cannot exceed 100 characters"],
      match: [
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/,
        "Password must be strong: at least 8 characters with uppercase, lowercase, number, and symbol.",
      ],
      select: false,
    },
    passwordChangedAt: { type: Date },
    passwordResetToken: {
      type: String,
      validate: {
        validator: (value) => !value || value.length === 64,
        message: "Invalid password reset token format.",
      },
    },
    passwordResetTokenExpiration: {
      type: Date,
      validate: {
        validator: (value) => !value || value > new Date(),
        message: "Password reset token has expired.",
      },
    },
    passwordHistory: {
      type: [String],
      select: false,
      default: [],
      validate: {
        validator: function (arr) {
          return arr.length <= 5;
        },
        message: "Password history exceeds limit.",
      },
    },
    otp: { type: String, select: false },
    otpExpiry: { type: Date, select: false },
    avatar: {
      url: {
        type: String,
        validate: {
          validator: (value) =>
            !value || /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(value),
          message: "Invalid avatar image URL format.",
        },
      },
      publicId: { type: String },
    },
    role: {
      type: String,
      enum: ["user", "admin", "superAdmin"],
      default: "user",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    loginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: { type: Date },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String, select: false },
    qrCode: { type: String, select: false },
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
// Index
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
UserSchema.plugin(mongooseDelete, {
  deletedAt: true,
  overrideMethods: "all",
});

UserSchema.plugin(mongooseHidden, {
  hidden: {
    password: true,
    otp: true,
    twoFactorSecret: true,
    qrCode: true,
    loginAttempts: true,
    lockUntil: true,
    passwordResetToken: true,
    passwordResetTokenExpiration: true,
  },
});

UserSchema.plugin(uniqueValidator, {
  message: "{PATH} already exists.",
});

// ==============================
// Pre-save Hook
// ==============================
UserSchema.pre("save", async function (next) {
  try {
    // Only proceed if password is modified
    if (this.isModified("password")) {
      // Validate password
      if (!this.password) {
        return next(
          new ApiError(StatusCodes.BAD_REQUEST, "Password is required")
        );
      }

      // Check if password is reused from history
      if (this.passwordHistory?.length > 0) {
        const isReused = await Promise.all(
          this.passwordHistory.map((oldHash) =>
            bcrypt.compare(this.password, oldHash)
          )
        );
        if (isReused.includes(true)) {
          return next(
            new ApiError(StatusCodes.BAD_REQUEST, "Password was used recently.")
          );
        }
      }

      // Hash new password
      const saltRound = await bcrypt.genSalt(salt);
      this.password = await bcrypt.hash(this.password, saltRound);
      this.passwordChangedAt = new Date();

      // Update password history (limit to 5 most recent)
      this.passwordHistory = [
        this.password,
        ...(this.passwordHistory || []),
      ].slice(0, 5);
    }

    // Only proceed if OTP is modified and exists
    if (this.isModified("otp") && this.otp) {
      const saltRound = await bcrypt.genSalt(salt);
      this.otp = await bcrypt.hash(this.otp, saltRound);
    }

    // Validate user schema
    const userJsonSchema = this.toJSONSchema();
    const validate = ajv.compile(userJsonSchema);
    if (!validate(this.toObject())) {
      return next(
        new ApiError(StatusCodes.BAD_REQUEST, validate.errors[0].message)
      );
    }

    next();
  } catch (error) {
    next(error);
  }
});

// ==============================
// Instance Methods
// ==============================
UserSchema.methods.comparePassword = async function (password) {
  if (!this.password) {
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Password not set for this user."
    );
  }
  const isMatch = await bcrypt.compare(password, this.password);
  if (!isMatch) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Incorrect password.");
  }
  return true;
};

UserSchema.methods.compareOTP = async function (otp) {
  if (!this.otp) {
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "OTP not set for this user."
    );
  }
  const isMatch = await bcrypt.compare(otp, this.otp);
  if (!isMatch) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Incorrect OTP.");
  }
  return true;
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
    { expiresIn: accessTokenExpiresIn }
  );
};

UserSchema.methods.generateRefreshToken = function () {
  return jwt.sign({ id: this._id }, refreshTokenSecret, {
    expiresIn: refreshTokenExpiresIn,
  });
};

UserSchema.methods.generateCryptoToken = function () {
  return crypto.randomBytes(32).toString("hex");
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

UserSchema.methods.revokeTokens = async function () {
  await Token.deleteMany({ userId: this._id });
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

UserSchema.methods.verifyTwoFactorCode = async function (user, token) {
  const isVerified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: "base32",
    token,
  });
  if (!isVerified) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid 2FA code.");
  }
  return true;
};

// ==============================
// Static Methods
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

  await Token.create([
    {
      userId: user._id,
      token: accessToken,
      type: "access",
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
    {
      userId: user._id,
      token: refreshToken,
      type: "refresh",
      expiresAt: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000),
    },
  ]);

  return { accessToken, refreshToken };
};

UserSchema.statics.generateTwoFactorAuth = async function (user) {
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `chatty (${user.email})`,
  });

  user.twoFactorSecret = secret.base32;
  user.twoFactorEnabled = true;
  await user.save();

  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

  return { qrCodeUrl, secret };
};

// ==============================
// Model Export
// ==============================
const User = mongoose.model("User", UserSchema);

export default User;
