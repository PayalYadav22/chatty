// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Constant
// ==============================
import { logEvents } from "../constants/constant.js";

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
      enum: logEvents,
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
