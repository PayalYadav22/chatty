// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Schema Definition
// ==============================
const messageSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Sender ID is required."],
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Receiver ID is required."],
    },
    content: {
      type: String,
      required: [true, "Content is required."],
      trim: true,
      minlength: [1, "Content cannot be empty."],
      maxlength: [1000, "Content cannot exceed 1000 characters."],
    },
    seen: {
      type: Boolean,
      default: false,
    },
    image: {
      url: {
        type: String,
        validate: {
          validator: (value) =>
            /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(value),
          message: "Invalid image URL format.",
        },
      },
      publicId: {
        type: String,
        required: [true, "Image publicId is required when an image is sent."],
      },
    },
    video: {
      url: {
        type: String,
        validate: {
          validator: (value) =>
            /^https?:\/\/.*\.(mp4|avi|mov|mkv)$/i.test(value),
          message:
            "Invalid video URL format. Only mp4, avi, mov, and mkv are allowed.",
        },
      },
      publicId: {
        type: String,
        required: [true, "Video publicId is required when a video is sent."],
      },
      duration: {
        type: Number,
        required: [true, "Video duration is required."],
        min: [1, "Video duration must be at least 1 second."],
      },
      thumbnailUrl: {
        type: String,
        validate: {
          validator: (value) =>
            /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(value),
          message: "Invalid thumbnail URL format.",
        },
      },
    },
    pinned: {
      type: Boolean,
      default: false,
    },
    reactions: [
      {
        userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        emoji: { type: String },
      },
    ],
  },
  { timestamps: true }
);

// ==============================
// Model Export
// ==============================
const Message = mongoose.model("Message", messageSchema);

export default Message;
