// ==============================
// External Packages
// ==============================
import jwt from "jsonwebtoken";
import { StatusCodes } from "http-status-codes";

// ==============================
// Models
// ==============================
import User from "../models/user.model.js";

// ==============================
// Middleware
// ==============================
import asyncHandler from "./asyncHandler.middleware.js";

// ==============================
// Utils
// ==============================
import ApiError from "../utils/apiError.js";

// ==============================
// Constants
// ==============================
import { accessTokenSecret } from "../constants/constant.js";

// ==============================
// Logger
// ==============================
import logger from "../logger/logger.js";

const authMiddleware = asyncHandler(async (req, _, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    logger.warn("AuthMiddleware: No token provided");
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Authentication required");
  }

  try {
    const decoded = jwt.verify(token, accessTokenSecret);
    const user = await User.findById(decoded._id).select(
      "-password -token -passwordResetToken -passwordResetTokenExpiration"
    );
    if (!user) {
      logger.warn("AuthMiddleware: User not found");
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not found");
    }
    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      logger.warn("AuthMiddleware: Token expired");
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Token expired");
    }
    if (error instanceof jwt.JsonWebTokenError) {
      logger.warn("AuthMiddleware: Invalid token format");
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid token");
    }

    logger.error(`AuthMiddleware: Unexpected error - ${error.message}`);
    throw error;
  }
});

export default authMiddleware;
