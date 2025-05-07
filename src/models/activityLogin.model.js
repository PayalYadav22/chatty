// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

import { logEvents } from "../constants/constant.js";

// ==============================
// Activity Log Schema
// ==============================
const ActivityLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    action: {
      type: String,
      required: true,
      enum: logEvents,
    },
    description: {
      type: String,
      default: "",
    },
    target: {
      type: {
        model: String,
        id: mongoose.Schema.Types.ObjectId,
      },
      default: null,
    },
    metadata: {
      ipAddress: String,
      userAgent: String,
      location: String,
      requestId: String,
      deviceFingerprint: String,
      additionalData: mongoose.Schema.Types.Mixed,
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  { versionKey: false }
);

// ==============================
// Indexes
// ==============================
ActivityLogSchema.index({ createdAt: -1 });
ActivityLogSchema.index({ userId: 1, createdAt: -1 });

// ==============================
// Export
// ==============================
const ActivityLog = mongoose.model("ActivityLog", ActivityLogSchema);
export default ActivityLog;
