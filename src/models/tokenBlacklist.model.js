// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Models
// ==============================
import User from "./user.model.js";

const TokenBlacklistSchema = new mongoose.Schema(
  {
    token: { type: String, required: true, unique: true },
    tokenHash: { type: String, unique: true },
    expiresAt: { type: Date, required: true },
    reason: { type: String, default: "Unknown" },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

const TokenBlacklist = mongoose.model("TokenBlacklist", TokenBlacklistSchema);

export default TokenBlacklist;
