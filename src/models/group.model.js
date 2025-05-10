// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Constants
// ==============================
import { privateOptions } from "../constants/constant.js";

// ==============================
// Group Schema
// ==============================
const groupSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Group name is required."],
      trim: true,
      minlength: [3, "Group name must be at least 3 characters."],
      maxlength: [100, "Group name cannot exceed 100 characters."],
    },
    description: {
      type: String,
      trim: true,
      maxlength: [500, "Description cannot exceed 500 characters."],
    },
    creatorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Creator ID is required."],
    },
    members: {
      type: [
        {
          userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
          },
          role: {
            type: String,
            enum: ["admin", "moderator", "member"],
            default: "member",
          },
          joinedAt: {
            type: Date,
            default: Date.now,
          },
        },
      ],
      validate: {
        validator: (members) => members.length <= 1000,
        message: "Group cannot have more than 1000 members.",
      },
    },
    privacy: {
      type: String,
      enum: privateOptions,
      default: "private",
    },
    settings: {
      allowMemberInvites: {
        type: Boolean,
        default: true,
      },
      muteNotifications: {
        type: Boolean,
        default: false,
      },
    },
    avatar: {
      url: {
        type: String,
        validate: {
          validator: (value) =>
            !value || /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(value),
          message: "Invalid avatar URL format.",
        },
      },
      publicId: String,
    },
    lastMessage: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Message",
    },
  },
  { timestamps: true }
);

// ==============================
// Indexes
// ==============================
groupSchema.index({ creatorId: 1 });
groupSchema.index({ "members.userId": 1 });
groupSchema.index({ privacy: 1 });

// ==============================
// Exports
// ==============================
const Group = mongoose.model("Group", groupSchema);

export default Group;
