// ==============================
// External Packages
// ==============================
import Session from "../../models/session.model.js";
import { UAParser } from "ua-parser-js";

// ==============================
// Helper: Parse Device Info
// ==============================
function parseDevice(userAgent) {
  const parser = new UAParser(userAgent);
  const result = parser.getResult();
  return {
    os: `${result.os.name || "Unknown"} ${result.os.version || ""}`.trim(),
    browser: `${result.browser.name || "Unknown"} ${
      result.browser.version || ""
    }`.trim(),
    device: result.device.type || "desktop",
  };
}

// ==============================
// Helper: Extract Metadata from Request
// ==============================
const extractSessionMetadata = (req) => {
  const ip = req?.ip || null;
  const userAgent = req?.get("User-Agent") || "unknown";
  const deviceInfo = parseDevice(userAgent);

  return {
    ip,
    userAgent,
    deviceInfo,
    deviceFingerprint: userAgent && ip ? `${userAgent}:${ip}` : undefined,
  };
};

// ==============================
// Session Creation Handler
// ==============================
const createSession = async ({ user, refreshToken, sessionExpiry, req }) => {
  const metadata = extractSessionMetadata(req);

  const refreshTokenHash = await user.hashSessionToken(refreshToken);

  const session = await Session.create({
    userId: user._id,
    refreshTokenHash,
    ip: metadata.ip,
    userAgent: metadata.userAgent,
    deviceInfo: metadata.deviceInfo,
    deviceFingerprint: metadata.deviceFingerprint,
    expiresAt: sessionExpiry,
  });

  return session;
};

// ==============================
// Export
// ==============================
export default createSession;
