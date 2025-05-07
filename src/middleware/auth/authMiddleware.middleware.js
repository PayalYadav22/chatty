// ==============================
// External Packages
// ==============================
import jwt from "jsonwebtoken";
import { StatusCodes } from "http-status-codes";

// ==============================
// Models
// ==============================
import User from "../../models/user.model.js";
import TokenBlacklist from "../../models/tokenBlacklist.model.js";

// ==============================
// Middleware
// ==============================
import asyncHandler from "../asyncHandler.middleware.js";

// ==============================
// Utils
// ==============================
import ApiError from "../../utils/apiError.js";

// ==============================
// Constants
// ==============================
import { accessTokenSecret } from "../../constants/constant.js";

// ==============================
// Logger
// ==============================
import logger from "../../logger/logger.js";

const authMiddleware = asyncHandler(async (req, _, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Authentication required");
  }

  const isBlacklisted = await TokenBlacklist.findOne({ token });

  if (isBlacklisted) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Token revoked");
  }

  let decoded;

  try {
    decoded = jwt.verify(token, accessTokenSecret);
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      decoded = jwt.decode(token);
      if (decoded) {
        const user = await User.findById(decoded.id);
        if (user && user.isTokenExpiredGracefully(error.expiredAt.getTime())) {
          logger.warn("AuthMiddleware: Token expired but within grace period.");
          throw new ApiError(
            StatusCodes.UNAUTHORIZED,
            "Logout attempt failed: Token expired but within grace period."
          );
        }
      }
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

  const user = await User.findById(decoded.id).select(
    "-password -passwordResetToken -passwordResetTokenExpiration -passwordHistory -otp -otpExpiry -twoFactorSecret -twoFactorEnabled"
  );

  if (!user) {
    logger.warn("AuthMiddleware: User not found");
    throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
  }

  if (user.changedPasswordAfter(decoded.iat)) {
    logger.warn("User recently changed password. Please log in again.");
    throw new ApiError(
      StatusCodes.UNAUTHORIZED,
      "User recently changed password. Please log in again."
    );
  }

  if (user.tokenVersion !== decoded.tokenVersion) {
    throw new ApiError(StatusCodes.FORBIDDEN, "Token has been revoked.");
  }

  req.user = user;
  next();
});

export default authMiddleware;
