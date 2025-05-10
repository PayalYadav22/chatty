// ==============================
// External Packanges
// ==============================
import mongoose from "mongoose";

// ==============================
// Message Schema
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
      },
      type: {
        type: String,
      },
      duration: {
        type: Number,
        required: function () {
          return !!this.video?.url;
        },
        min: [1, "Video duration must be at least 1 second."],
      },
      thumbnailUrl: {
        type: String,
        validate: {
          validator: (value) =>
            /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(value),
          message: "Invalid thumbnail image URL format.",
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
    labels: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true,
        },
        label: {
          type: String,
          required: true,
          enum: ["Important", "Work", "Personal", "Spam", "ToDo"],
        },
      },
    ],
    forwardedFrom: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Message",
    },
  },
  { timestamps: true }
);

// ==============================
// Indexs
// ==============================
messageSchema.index({ senderId: 1, receiverId: 1, createdAt: 1 });
messageSchema.index({ content: "text" });
messageSchema.index({ seen: 1 });
messageSchema.index({ "image.url": 1 });
messageSchema.index({ "video.url": 1 });
messageSchema.index({ "reactions.emoji": 1 });
messageSchema.index({ pinned: 1 });
messageSchema.index({ "labels.label": 1 });

// ==============================
// Exports
// ==============================
const Message = mongoose.model("Message", messageSchema);
export default Message;
