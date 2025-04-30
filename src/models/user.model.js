// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { StatusCodes } from "http-status-codes";

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
} from "../constants/constant.js";

// ==============================
// Schema Definition
// ==============================
const UserSchema = mongoose.Schema(
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
      select: false,
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
      minlength: [6, "Password must be at least 6 characters long"],
      maxlength: [20, "Password cannot exceed 20 characters"],
    },
    passwordResetToken: {
      type: String,
      validate: {
        validator: (value) => {
          return value ? value.length === 32 : true;
        },
        message: "Invalid password reset token format.",
      },
    },
    passwordResetTokenExpiration: {
      type: Date,
      validate: {
        validator: (value) => {
          return value ? value > new Date() : true;
        },
        message: "Password reset token has expired.",
      },
    },
    avatar: {
      url: {
        type: String,
        validate: {
          validator: (value) => {
            return value
              ? /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(value)
              : true;
          },
          message: "Invalid avatar image URL format.",
        },
      },
      publicId: {
        type: String,
      },
    },
    role: {
      type: String,
      enum: ["user", "admin", "superAdmin"],
      default: "user",
      required: [true, "Role is required."],
    },
    token: {
      accessToken: {
        type: String,
        select: false,
      },
      refreshToken: {
        type: String,
        select: false,
      },
    },
  },
  { timestamps: true }
);

// ==============================
// Schema Hooks
// ==============================
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const saltRounds = Number(salt);
    const salt = await bcrypt.genSalt(saltRounds);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// ==============================
// Schema Methods
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

UserSchema.methods.generateAccessToken = async function () {
  return jwt.sign(
    {
      id: this._id,
      fullName: this.fullName,
      email: this.email,
      userName: this.userName,
      phone: this.phone,
      role: this.role,
    },
    accessTokenSecret,
    { expiresIn: accessTokenExpiresIn }
  );
};

UserSchema.methods.generateRefreshToken = async function () {
  return jwt.sign(
    {
      id: this._id,
    },
    refreshTokenSecret,
    { expiresIn: refreshTokenExpiresIn }
  );
};

UserSchema.methods.generateCryptoToken = async function () {
  return crypto.randomBytes(32).toString("hex");
};

// ==============================
// Schema Statics
// ==============================
UserSchema.statics.generateToken = async function (id) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid ID format.");
  }

  const user = await User.findById(id);

  if (!user) {
    throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
  }

  const accessToken = await user.generateAccessToken();
  const refreshToken = await user.generateRefreshToken();

  user.token = {
    accessToken,
    refreshToken,
  };

  await user.save({ validateBeforeSave: false });

  return { accessToken, refreshToken };
};

// ==============================
// Model Export
// ==============================
const User = mongoose.model("User", UserSchema);

export default User;
