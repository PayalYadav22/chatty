import { StatusCodes } from "http-status-codes";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import Message from "../../models/message.model.js";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import { uploadFileToCloudinary } from "../../config/cloudinary.config.js";

const MessageController = {
  sendMessage: asyncHandler(async (req, res) => {
    const { content } = req.body;
    const { id: receiverId } = req.params;
    const senderId = req.user?._id;

    [senderId, receiverId].forEach((id) => {
      if (!mongoose.Types.ObjectId.isValid(id)) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Invalid sender or receiver ID."
        );
      }
    });

    if (!content) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Message content is required."
      );
    }

    const imageLocalFilePath = req?.file?.path;

    if (!imageLocalFilePath) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "No image file provided.");
    }

    const uploadedFile = await uploadFileToCloudinary(imageLocalFilePath);

    if (!uploadedFile?.url || !uploadedFile?.public_id) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to upload image."
      );
    }

    const message = await Message.create({
      senderId,
      receiverId,
      content: content?.trim() || "",
      image: {
        url: uploadedFile.url,
        publicId: uploadedFile.public_id,
      },
    });

    return new ApiResponse(
      StatusCodes.CREATED,
      message,
      "Message sent successfully"
    ).send(res);
  }),

  getMessage: asyncHandler(async (req, res) => {
    const { id: userToChatId } = req.params;
    const senderId = req.user?._id;

    if (![senderId, userToChatId].every(mongoose.Types.ObjectId.isValid)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid sender or receiver ID."
      );
    }

    if (!userToChatId || !senderId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Missing user information.");
    }

    const messages = await Message.find({
      $or: [
        { senderId, receiverId: userToChatId },
        { senderId: userToChatId, receiverId: senderId },
      ],
    })
      .sort({ createdAt: 1 })
      .populate("senderId", "fullName userName avatar")
      .populate("receiverId", "fullName userName avatar");

    return new ApiResponse(
      StatusCodes.OK,
      messages,
      "Conversation fetched successfully"
    ).send(res);
  }),

  getUnseenMessages: asyncHandler(async (req, res) => {
    const receiverId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(receiverId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user ID.");
    }

    const unseenMessages = await Message.find({
      receiverId,
      seen: false,
    })
      .sort({ createdAt: -1 })
      .populate("senderId", "fullName userName avatar")
      .populate("receiverId", "fullName userName avatar");

    return new ApiResponse(
      StatusCodes.OK,
      unseenMessages,
      "Unseen messages fetched successfully."
    ).send(res);
  }),

  markAsSeen: asyncHandler(async (req, res) => {
    const receiverId = req.user?._id;
    const { id: senderId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(senderId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid sender ID.");
    }

    const result = await Message.updateMany(
      { senderId, receiverId, seen: false },
      { $set: { seen: true } }
    );

    return new ApiResponse(
      StatusCodes.OK,
      result,
      "Messages from sender marked as seen."
    ).send(res);
  }),

  deleteMessage: asyncHandler(async (req, res) => {
    const { id: messageId } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(messageId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid message ID.");
    }

    const message = await Message.findById(messageId);

    if (!message) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Message not found.");
    }

    if (
      message.senderId.toString() !== userId.toString() &&
      message.receiverId.toString() !== userId.toString()
    ) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Not authorized to delete this message."
      );
    }

    await message.deleteOne();

    return new ApiResponse(
      StatusCodes.OK,
      null,
      "Message deleted successfully."
    ).send(res);
  }),

  updateMessageContent: asyncHandler(async (req, res) => {
    const { id: messageId } = req.params;
    const { content } = req.body;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(messageId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid message ID.");
    }

    if (!content) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Content is required.");
    }

    const message = await Message.findById(messageId);

    if (!message) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Message not found.");
    }

    if (message.senderId.toString() !== userId.toString()) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You can only update your own messages."
      );
    }

    message.content = content.trim();
    await message.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      message,
      "Message content updated successfully."
    ).send(res);
  }),

  searchMessages: asyncHandler(async (req, res) => {
    const { query, page = 1, limit = 20 } = req.query;
    const filters = [];

    if (!query) {
      return new ApiError(StatusCodes.BAD_REQUEST, "Query is required.");
    }

    filters.push({ content: { $regex: query, $options: "i" } });

    if (mongoose.Types.ObjectId.isValid(query)) {
      filters.push({ senderId: query });
      filters.push({ receiverId: query });
    }

    const lowered = query.toLowerCase();

    if (["true", "false"].includes(lowered)) {
      filters.push({ seen: lowered === "true" });
    }

    if (lowered === "hasimage") {
      filters.push({ "image.url": { $exists: true, $ne: null } });
    }

    if (lowered === "hasvideo") {
      filters.push({ "video.url": { $exists: true, $ne: null } });
    }

    const skip = (Number(page) - 1) * Number(limit);

    const messages = await Message.find({ $or: filters })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .populate("senderId", "username avatar")
      .populate("receiverId", "username avatar");

    const total = await Message.countDocuments({ $or: filters });

    return new ApiResponse(
      StatusCodes.OK,
      {
        success: true,
        total,
        page: Number(page),
        limit: Number(limit),
        messages,
      },
      "Messages fetched successfully."
    ).send(res);
  }),

  forwardMessage: asyncHandler(async (req, res) => {
    const { messageId, newReceiverId } = req.body;
    const senderId = req.user._id;

    if (!messageId || !newReceiverId) {
      return new ApiResponse(
        StatusCodes.BAD_REQUEST,
        null,
        "messageId and newReceiverId are required."
      ).send(res);
    }

    const original = await Message.findById(messageId);

    if (!original) {
      return new ApiResponse(
        StatusCodes.NOT_FOUND,
        null,
        "Original message not found."
      ).send(res);
    }

    const forwarded = await Message.create({
      senderId,
      receiverId: newReceiverId,
      content: original.content,
      image: original.image?.url ? original.image : undefined,
      video: original.video?.url ? original.video : undefined,
    });

    return new ApiResponse(
      StatusCodes.CREATED,
      { message: forwarded },
      "Message forwarded successfully."
    ).send(res);
  }),

  reactToMessage: asyncHandler(async (req, res) => {
    const { messageId, emoji } = req.body;
    const userId = req.user._id;

    if (!messageId || !emoji) {
      return new ApiResponse(
        StatusCodes.BAD_REQUEST,
        null,
        "messageId and emoji are required."
      ).send(res);
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return new ApiResponse(
        StatusCodes.NOT_FOUND,
        null,
        "Message not found."
      ).send(res);
    }

    const existingReactionIndex = message.reactions.findIndex((r) =>
      r.userId.equals(userId)
    );

    if (existingReactionIndex >= 0) {
      message.reactions[existingReactionIndex].emoji = emoji;
    } else {
      message.reactions.push({ userId, emoji });
    }

    await message.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      { message },
      "Reaction updated successfully."
    ).send(res);
  }),

  pinMessage: asyncHandler(async (req, res) => {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);

    if (!message) {
      return new ApiResponse(
        StatusCodes.NOT_FOUND,
        null,
        "Message not found."
      ).send(res);
    }

    if (message.pinned) {
      return new ApiResponse(
        StatusCodes.BAD_REQUEST,
        null,
        "Message is already pinned."
      ).send(res);
    }

    message.pinned = true;
    await message.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      { message },
      "Message pinned successfully."
    ).send(res);
  }),

  unpinMessage: asyncHandler(async (req, res) => {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);

    if (!message) {
      return new ApiResponse(
        StatusCodes.NOT_FOUND,
        null,
        "Message not found."
      ).send(res);
    }

    if (!message.pinned) {
      return new ApiResponse(
        StatusCodes.BAD_REQUEST,
        null,
        "Message is not pinned."
      ).send(res);
    }

    message.pinned = false;
    await message.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      { message },
      "Message unpinned successfully."
    ).send(res);
  }),
};

export default MessageController;
