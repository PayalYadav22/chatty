// ==============================
// External Packages
// ==============================
import { StatusCodes } from "http-status-codes";

// ==============================
// Utils
// ==============================
import ApiError from "../../utils/apiError.js";

// ==============================
// Only for Admin
// ==============================
export const isAdmin = (req, res, next) => {
  const user = req.user;
  if (!user || user.role !== "admin") {
    return next(
      new ApiError(StatusCodes.FORBIDDEN, "You don't have admin access")
    );
  }
  next();
};

// ==============================
// Only for SuperAdmin
// ==============================
export const isSuperAdmin = (req, res, next) => {
  const user = req.user;
  if (!user || user.role !== "superAdmin") {
    return next(
      new ApiError(StatusCodes.FORBIDDEN, "You don't have super admin access")
    );
  }
  next();
};

// ==============================
// SuperAdmin + Admin
// ==============================
export const isAdminOrSuperAdmin = (req, res, next) => {
  const user = req.user;
  if (!user || (user.role !== "admin" && user.role !== "superAdmin")) {
    return next(
      new ApiError(
        StatusCodes.FORBIDDEN,
        "You must be an admin or super admin to access this route"
      )
    );
  }
  next();
};
