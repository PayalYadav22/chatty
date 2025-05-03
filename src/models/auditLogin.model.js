// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Audit Log Schema
// ==============================
const AuditLogSchema = new mongoose.Schema(
  {
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    targetId: { type: mongoose.Schema.Types.ObjectId },
    targetModel: { type: String },
    eventType: {
      type: String,
      required: true,
      enum: [
        "REGISTER_FAILED",
        "REGISTER_SUCCESS",
        "VERIFIED_EMAIL_FAILED",
        "VERIFIED_EMAIL_SUCCESS",
        "LOGIN_FAILED",
        "LOGIN_SUCCESS",
        "PASSWORD_RESET_REQUEST_FAILED",
        "PASSWORD_RESET_REQUEST_SUCCESS",
        "LOGOUT_FAILED",
        "LOGOUT_SUCCESS",
        "REFRESH_TOKEN_FAILED",
        "REFRESH_TOKEN_SUCCESS",
        "SESSION_ACTIVE",
        "SESSION_REACTIVATED",
        "SESSION_INVALIDATED",
        "PASSWORD_RESET_SECURITY_QUESTION_PROMPTED",
        "PASSWORD_RESET_SECURITY_ANSWER_FAILED",
        "PASSWORD_RESET_SECURITY_ANSWER_SUCCESS",
        "PASSWORD_RESET_REJECTED_DUE_TO_REUSED_PASSWORD",
        "PASSWORD_RESET_SUCCESS",
        "OTP_EMAIL_SEND_SUCCESS",
        "OTP_RESET_REQUEST_FAILED",
        "TOKENBLACK_LIST_READ",
        "TOKENBLACK_LIST_REMOVE",
        "SESSION_CREATE",
        "SESSION_LIST",
        "SESSION_VIEW_FAIL",
        "SESSION_VIEW",
        "SESSION_INVALIDATE",
        "SESSION_INVALIDATE_FAIL",
        "SESSION_COUNT_FAIL",
        "SESSION_COUNT_SUCCESS",
        "LOGOUT_ALL_SESSIONS",
      ],
    },
    description: { type: String },
    metadata: {
      ipAddress: String,
      userAgent: String,
      location: String,
      requestId: String,
      deviceFingerprint: String,
      changes: mongoose.Schema.Types.Mixed,
    },
    createdAt: { type: Date, default: Date.now, index: true },
  },
  { versionKey: false }
);

// ==============================
// Indexes
// ==============================
AuditLogSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 90 }
);

// ==============================
// Export
// ==============================
const AuditLog = mongoose.model("AuditLog", AuditLogSchema);
export default AuditLog;
