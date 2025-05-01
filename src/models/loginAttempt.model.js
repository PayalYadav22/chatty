import mongoose from "mongoose";

const LoginAttemptSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    email: String,
    ip: String,
    userAgent: String,
    success: Boolean,
    reason: String,
  },
  { timestamps: true }
);

const LoginAttempt = mongoose.model("LoginAttempt", LoginAttemptSchema);

LoginAttemptSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 90 }
);

export default LoginAttempt;
