// ==============================
// Model
// ==============================
import LoginAttempt from "../../models/loginAttempt.model.js";

// ==============================
// Request Meta Data
// ==============================
const extractRequestMetadata = (req, changes = {}) => {
  const ip = req?.ip || null;
  const userAgent = req?.get("User-Agent") || null;
  return {
    ipAddress: ip,
    userAgent,
    location: req?.geo?.city || null,
    requestId: req?.id || null,
    deviceFingerprint: userAgent && ip ? `${userAgent}:${ip}` : undefined,
    changes,
  };
};

const logLoginAttempt = async ({ user, email, success, reason, req }) => {
  const metadata = extractRequestMetadata(req);

  await LoginAttempt.create({
    user,
    email,
    success,
    reason,
    ip: metadata.ipAddress,
    userAgent: metadata.userAgent,
    deviceFingerprint: metadata.deviceFingerprint,
    location: metadata.location,
    metadata,
  });
};

// ==============================
// Export
// ==============================
export default logLoginAttempt;
