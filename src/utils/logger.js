// ==============================
// External Packages
// ==============================
import { StatusCodes } from "http-status-codes";

// ==============================
// Services
// ==============================
import createActivityLog from "../services/log/createActivityLog.service.js";
import createAuditLog from "../services/log/createAuditLog.service.js";
import createSession from "../services/log/createSession.service.js";
import createLoginAttempt from "../services/log/createLoginAttempt.service.js";

// ==============================
// Logger
// ==============================
import logger from "logger/logger.js";

// ==============================
// Utils
// ==============================
import ApiError from "./apiError.js";

export const logAudit = async (options) => {
  try {
    await createAuditLog(options);
  } catch (err) {
    logger.error("Audit log error:", err);
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      `Audit log error: ${err}`
    );
  }
};

export const logActivity = async (options) => {
  try {
    await createActivityLog(options);
  } catch (err) {
    logger.error("Activity log error:", err);
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      `Activity log error: ${err}`
    );
  }
};

export const logSession = async (options) => {
  try {
    await createSession(options);
  } catch (err) {
    logger.error("Session log error:", err);
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      `Session log error: ${err}`
    );
  }
};

export const logLoginAttempt = async (options) => {
  try {
    await createLoginAttempt(options);
  } catch (err) {
    logger.error("Login Attempt log error:", err);
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      `Login Attempt log error: ${err}`
    );
  }
};
