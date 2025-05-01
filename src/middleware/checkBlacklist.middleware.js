// ==============================
// External Packages
// ==============================
import { StatusCodes } from "http-status-codes";

// ==============================
// Models
// ==============================
import { TokenBlacklist } from "../models/user.model.js";

// ==============================
// Utils
// ==============================
import ApiError from "../utils/apiError.js";

export const checkBlacklist = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken || req.headers.authorization?.split(" ")[1];

  if (!token) return next();

  const blacklisted = await TokenBlacklist.findOne({ token });
  if (blacklisted) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, "This token has been revoked");
  }

  next();
});
