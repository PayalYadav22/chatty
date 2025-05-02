// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Login Attempt Schema
// ==============================
const LoginAttemptSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
    },
    email: {
      type: String,
      index: true,
      lowercase: true,
      trim: true,
    },
    ip: {
      type: String,
    },
    userAgent: {
      type: String,
    },
    deviceFingerprint: {
      type: String,
      index: true,
    },
    location: {
      type: String,
    },
    success: {
      type: Boolean,
      required: true,
      index: true,
    },
    reason: {
      type: String,
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
    },
  },
  { timestamps: true }
);

// ==============================
// Indexes
// ==============================
LoginAttemptSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 90 }
);

// ==============================
// Pre-save
// ==============================
LoginAttemptSchema.pre("save", function (next) {
  if (!this.deviceFingerprint && this.userAgent && this.ip) {
    this.deviceFingerprint = `${this.userAgent}:${this.ip}`;
  }
  next();
});

// ==============================
// Export
// ==============================
const LoginAttempt = mongoose.model("LoginAttempt", LoginAttemptSchema);

export default LoginAttempt;
