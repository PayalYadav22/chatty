// ==============================
// External Package
// ==============================
import { UAParser } from "ua-parser-js";

// ==============================
// Model
// ==============================
import ActivityLog from "../models/activityLogin.model.js";

// ==============================
// logger
// ==============================
import logger from "../logger/logger.js";

// ==============================
// Helper Function for Device Parsing
// ==============================
function parseDevice(userAgent) {
  const parser = new UAParser(userAgent);
  const result = parser.getResult();
  return {
    os: result.os.name + " " + result.os.version,
    browser: result.browser.name + " " + result.browser.version,
    device: result.device.type || "desktop",
  };
}

// ==============================
// Request Meta Data
// ==============================
const extractRequestMetadata = (req, additionalData = {}) => {
  const ip = req?.ip || null;
  const userAgent = req?.get("User-Agent") || null;
  const deviceInfo = userAgent ? parseDevice(userAgent) : {};

  return {
    ipAddress: ip,
    userAgent,
    location: req?.geo?.city || null,
    requestId: req?.id || null,
    deviceFingerprint: userAgent && ip ? `${userAgent}:${ip}` : undefined,
    device: deviceInfo.device,
    os: deviceInfo.os,
    browser: deviceInfo.browser,
    additionalData,
  };
};

// ==============================
// Create Activity Log Entry
// ==============================
const createActivityLog = async ({
  userId,
  action,
  description = "",
  target = null,
  req,
  additionalData = {},
}) => {
  if (!userId || !action) return;

  try {
    await ActivityLog.create({
      userId,
      action,
      description,
      target,
      metadata: extractRequestMetadata(req, additionalData),
    });
  } catch (error) {
    logger.error("Failed to create audit log:", error);
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Error creating audit log."
    );
  }
};

// ==============================
// Export
// ==============================
export default createActivityLog;
