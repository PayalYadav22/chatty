// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Session Schema
// ==============================
const sessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    refreshTokenHash: {
      type: String,
      required: true,
    },
    ip: {
      type: String,
    },
    userAgent: {
      type: String,
    },
    deviceInfo: {
      os: String,
      browser: String,
      device: String,
    },
    deviceFingerprint: {
      type: String,
      index: true,
    },
    isValid: {
      type: Boolean,
      default: true,
      index: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

// ==============================
// Indexes
// ==============================
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ==============================
// Pre-save
// ==============================
sessionSchema.pre("save", function (next) {
  if (!this.deviceFingerprint && this.userAgent && this.ip) {
    this.deviceFingerprint = `${this.userAgent}:${this.ip}`;
  }
  next();
});

// ==============================
// Export
// ==============================
const Session = mongoose.model("Session", sessionSchema);
export default Session;
