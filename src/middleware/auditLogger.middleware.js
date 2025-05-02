// ==============================
// Model
// ==============================
import AuditLog from "../models/auditLogin.model.js";
import { UAParser } from "ua-parser-js";

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
const extractRequestMetadata = (req, changes = {}) => {
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
    changes,
  };
};

const createAuditLog = async ({
  actorId,
  targetId,
  targetModel,
  eventType,
  description,
  changes = {},
  req,
}) => {
  await AuditLog.create({
    actorId,
    targetId,
    targetModel,
    eventType,
    description,
    metadata: extractRequestMetadata(req, changes),
  });
};

// ==============================
// Export
// ==============================
export default createAuditLog;
