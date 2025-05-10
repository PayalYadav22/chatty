// ==============================
// Socket.io
// ==============================
import { Server } from "socket.io";

// ==============================
// Expernal Packages
// ==============================
import { StatusCodes } from "http-status-codes";

// ==============================
// Model Schema
// ==============================
import Message from "../../models/message.model.js";

// ==============================
// Middlewares
// ==============================
import asyncHandler from "../../middleware/asyncHandler.middleware.js";

// ==============================
// Constants
// ==============================
import { validLabels, validVideo } from "../../constants/constant.js";

// ==============================
// Configs
// ==============================
import {
  uploadFileToCloudinary,
  deleteFileToCloudinary,
} from "../../config/cloudinary.config.js";

// ==============================
// Utils
// ==============================
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";

// ==============================
// Controllers
// ==============================
const MessageController = {
  sendMessage: asyncHandler(async (req, res) => {
    const { content = "", duration, thumbnailUrl } = req.body;
    const { id: receiverId } = req.params;
    const senderId = req.user?._id;

    if (![senderId, receiverId].every(mongoose.Types.ObjectId.isValid)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid sender or receiver ID."
      );
    }

    if (!content.trim() || content.trim().length > 1000) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Message content is required and must be under 1000 characters."
      );
    }

    const messageData = {
      senderId,
      receiverId,
      content: trimmedContent,
    };

    const localFilePath = req?.file?.path;
    const mimeType = req?.file?.mimetype;

    let uploadedFile = null;

    if (localFilePath && mimeType) {
      const isVideo = mimeType.startsWith("video/");

      if (isVideo && !validVideo.includes(mimeType)) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Invalid video format. Supported formats: mp4, avi, mkv."
        );
      }

      try {
        uploadedFile = await uploadFileToCloudinary(
          localFilePath,
          isVideo ? "video" : "image"
        );
      } catch (error) {
        logger.error(`Cloudinary upload failed: ${error.message}`);
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to upload media."
        );
      }

      if (!uploadedFile?.url || !uploadedFile?.public_id) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to upload media."
        );
      }

      if (isVideo) {
        if (!duration || isNaN(duration)) {
          throw new ApiError(
            StatusCodes.BAD_REQUEST,
            "Video duration is required and must be a number."
          );
        }
      }

      messageData.video = {
        url: uploadedFile.url,
        publicId: uploadedFile.public_id,
        type: mimeType,
        duration: parseFloat(duration),
      };

      if (thumbnailUrl) {
        const isValidThumbnail = /^https?:\/\/.*\.(jpg|jpeg|png|gif)$/i.test(
          thumbnailUrl
        );

        if (!isValidThumbnail) {
          throw new ApiError(
            StatusCodes.BAD_REQUEST,
            "Invalid thumbnail URL format."
          );
        }
        messageData.video.thumbnailUrl = thumbnailUrl;
      } else {
        messageData.image = {
          url: uploadedFile.url,
          publicId: uploadedFile.public_id,
        };
      }
    }

    const message = await Message.create(messageData);

    io.to(receiverId.toString()).emit("newMessage", message);

    return new ApiResponse(
      StatusCodes.CREATED,
      message,
      "Message sent successfully"
    ).send(res);
  }),

  getMessage: asyncHandler(async (req, res) => {
    const { id: userToChatId } = req.params;
    const senderId = req.user?._id;
    const { page = 1, limit = 10 } = req.query;

    if (![senderId, userToChatId].every(mongoose.Types.ObjectId.isValid)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid sender or receiver Id."
      );
    }

    if (!userToChatId || !senderId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Missing user information.");
    }

    const pageNumber = parseInt(page, 10);
    const limitNumber = parseInt(limit, 10);

    if (isNaN(pageNumber) || pageNumber <= 0) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid page number.");
    }

    if (isNaN(limitNumber) || limitNumber <= 0) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid limit value.");
    }

    const skip = (pageNumber - 1) * limitNumber;

    const messages = await Message.find({
      $or: [
        { senderId, receiverId: userToChatId },
        { senderId: userToChatId, receiverId: senderId },
      ],
    })
      .sort({ createdAt: 1 })
      .skip(skip)
      .limit(limitNumber)
      .populate("senderId", "fullName userName avatar")
      .populate("receiverId", "fullName userName avatar");

    const total = await Message.countDocuments({
      $or: [
        { senderId, receiverId: userToChatId },
        { senderId: userToChatId, receiverId: senderId },
      ],
    });

    return new ApiResponse(
      StatusCodes.OK,
      {
        messages,
        total,
        page: pageNumber,
        limit: limitNumber,
      },
      "Conversation fetched successfully"
    ).send(res);
  }),

  getUnseenMessages: asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;

    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated.");
    }

    const receiverId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(receiverId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user ID.");
    }

    const pageCount = parseInt(page, 10);
    const limitCount = parseInt(limit, 10);

    if (isNaN(pageCount) || pageCount <= 0) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid page number.");
    }

    if (isNaN(limitCount) || limitCount <= 0) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid limit value.");
    }

    const skip = (pageCount - 1) * limitCount;

    const user = await mongoose.model("User").findById(receiverId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const unseenMessages = await Message.find({
      receiverId,
      seen: false,
    })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitCount)
      .populate("senderId", "fullName userName avatar");

    const totalUnseenMessages = await Message.countDocuments({
      receiverId,
      seen: false,
    });

    return new ApiResponse(
      StatusCodes.OK,
      {
        totalUnseenMessages,
        page: pageCount,
        limit: limitCount,
        messages: unseenMessages,
        isEmpty: unseenMessages.length === 0,
      },
      "Unseen messages fetched successfully."
    ).send(res);
  }),

  markAsSeen: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated.");
    }

    const receiverId = req.user._id;
    const { id: senderId } = req.params;

    if (![senderId, receiverId].every(mongoose.Types.ObjectId.isValid)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid sender or receiver ID."
      );
    }

    const [sender, receiver] = await Promise.all([
      mongoose.model("User").findById(senderId),
      mongoose.model("User").findById(receiverId),
    ]);

    if (!sender || !receiver) {
      throw new ApiError(StatusCodes.NOT_FOUND, "One or both users not found.");
    }

    const result = await Message.updateMany(
      { senderId, receiverId, seen: false },
      { $set: { seen: true } }
    );

    if (result.modifiedCount > 0) {
      const senderSocketId = getSocketIdForUser(senderId);
      if (senderSocketId) {
        io.to(senderSocketId).emit("messagesSeen", {
          receiverId,
          senderId,
          messageCount: result.modifiedCount,
        });
      }
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        modifiedCount: result.modifiedCount,
        isUpdated: result.modifiedCount > 0,
      },
      result.modifiedCount > 0
        ? "Messages from sender marked as seen."
        : "No unseen messages to mark."
    ).send(res);
  }),

  deleteMessage: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated.");
    }

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

    try {
      if (message.image?.publicId) {
        await deleteFileToCloudinary(message.image.publicId);
      }

      if (message.video?.publicId) {
        await deleteFileToCloudinary(message.video.publicId);
      }
    } catch (error) {
      logger.error(`Cloudinary deletion failed: ${error.message}`);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to delete media."
      );
    }

    await message.deleteOne();

    const senderSocketId = getSocketIdForUser(message.senderId.toString());
    const receiverSocketId = getSocketIdForUser(message.receiverId.toString());

    const payload = {
      messageId,
      deletedBy: userId,
    };

    if (senderSocketId) {
      io.to(senderSocketId).emit("messageDeleted", payload);
    }

    if (receiverSocketId) {
      io.to(receiverSocketId).emit("messageDeleted", payload);
    }

    return new ApiResponse(
      StatusCodes.OK,
      { messageId },
      "Message deleted successfully."
    ).send(res);
  }),

  updateMessageContent: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated.");
    }

    const { id: messageId } = req.params;
    const { content } = req.body;
    const userId = req.user._id;

    if (![messageId, userId].every(mongoose.Types.ObjectId.isValid)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid message or user ID."
      );
    }

    if (!content || !content.trim()) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Content is required.");
    }

    const user = await mongoose.model("User").findById(userId);
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
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

    const updatedMessage = await Message.findOneAndUpdate(
      { _id: messageId, senderId: userId },
      { $set: { content: content.trim() } },
      { new: true, runValidators: true }
    );

    if (!updatedMessage) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Message not found or not authorized."
      );
    }

    const senderSocketId = getSocketIdForUser(
      updatedMessage.senderId.toString()
    );
    const receiverSocketId = getSocketIdForUser(
      updatedMessage.receiverId.toString()
    );

    if (senderSocketId) {
      io.to(senderSocketId).emit("messageUpdated", updatedMessage);
    }

    if (receiverSocketId) {
      io.to(receiverSocketId).emit("messageUpdated", updatedMessage);
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        _id: updatedMessage._id,
        content: updatedMessage.content,
        updatedAt: updatedMessage.updatedAt,
      },
      "Message content updated successfully."
    ).send(res);
  }),

  searchMessages: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated.");
    }

    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user ID.");
    }

    const { query, page = 1, limit = 20, reaction } = req.query;

    if (!query || !query.trim()) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Search query is required.");
    }

    const filters = [];

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

    if (reaction) {
      filters.push({ "reactions.emoji": reaction });
    }

    const pageCount = Number(page);
    const limitCount = Number(limit);
    const skip = (pageCount - 1) * limitCount;

    const queryFilter = {
      $and: [
        {
          $or: [{ senderId: userId }, { receiverId: userId }],
        },
        {
          $or: filters,
        },
      ],
    };

    const [messages, total] = await Promise.all([
      Message.find(queryFilter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitCount)
        .populate("senderId", "username avatar")
        .populate("receiverId", "username avatar"),
      Message.countDocuments(queryFilter),
    ]);

    return new ApiResponse(
      StatusCodes.OK,
      {
        success: true,
        total,
        pageCount,
        limitCount,
        data: messages,
      },
      "Messages fetched successfully."
    ).send(res);
  }),

  forwardMessage: asyncHandler(async (req, res) => {
    const { messageId, newReceiverId } = req.body;
    const senderId = req.user._id;

    if (!messageId || !newReceiverId) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "messageId and newReceiverId are required."
      );
    }

    if (
      ![messageId, newReceiverId, senderId].every(
        mongoose.Types.ObjectId.isValid
      )
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid message, sender, or receiver ID."
      );
    }

    const [original, senderUser, receiverUser] = await Promise.all([
      Message.findById(messageId),
      mongoose.model("User").findById(senderId),
      mongoose.model("User").findById(newReceiverId),
    ]);

    if (!senderUser) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Sender not found.");
    }

    if (!receiverUser) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Receiver not found.");
    }

    if (!original) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Original message not found.");
    }

    if (original.senderId.toString() !== senderId.toString()) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not authorized to forward this message."
      );
    }

    const messageData = {
      senderId,
      receiverId: newReceiverId,
      content: original.content || undefined,
      image: original.image?.url ? original.image : undefined,
      video: original.video?.url ? original.video : undefined,
      isForwarded: true,
      forwardedFrom: original._id,
    };

    if (!messageData.content && !messageData.image && !messageData.video) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Cannot forward an empty message (no content, image, or video)."
      );
    }

    const forwarded = await Message.create(messageData);

    const receiverSocketId = getSocketIdForUser(newReceiverId.toString());

    if (receiverSocketId) {
      io.to(receiverSocketId).emit("newMessage", forwarded);
    }

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
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "messageId and emoji are required."
      );
    }

    if (!mongoose.Types.ObjectId.isValid(messageId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid messageId.");
    }

    const message = await Message.findById(messageId);

    if (!message) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Message not found.");
    }

    const existingReactionIndex = message.reactions.findIndex((r) =>
      r.userId.equals(userId)
    );

    let updatedReactions;

    if (existingReactionIndex >= 0) {
      message.reactions[existingReactionIndex].emoji = emoji;
      updatedReactions = message.reactions;
    } else {
      updatedReactions = [...message.reactions, { userId, emoji }];
    }

    const updatedMessage = await Message.findOneAndUpdate(
      { _id: messageId },
      { reactions: updatedReactions },
      { new: true, runValidators: true }
    )
      .populate("senderId", "username avatar")
      .populate("receiverId", "username avatar");

    const reactionPayload = {
      messageId: updatedMessage._id,
      userId: userId.toString(),
      emoji,
    };

    io.to(updatedMessage.senderId._id.toString()).emit(
      "messageReactionUpdated",
      reactionPayload
    );
    io.to(updatedMessage.receiverId._id.toString()).emit(
      "messageReactionUpdated",
      reactionPayload
    );

    return new ApiResponse(
      StatusCodes.OK,
      { message: updatedMessage },
      "Reaction updated successfully."
    ).send(res);
  }),

  pinMessage: asyncHandler(async (req, res) => {
    const { messageId } = req.params;
    const userId = req.user._id;

    if (!messageId || !mongoose.Types.ObjectId.isValid(messageId)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid or missing message ID."
      );
    }

    const message = await Message.findById(messageId);

    if (!message) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Message not found.");
    }

    if (
      !message.senderId.equals(userId) &&
      !message.receiverId.equals(userId)
    ) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not authorized to pin this message."
      );
    }

    if (message.pinned) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Message is already pinned.");
    }

    message.pinned = true;
    await message.save();

    const payload = {
      messageId: message._id,
      pinned: true,
    };

    io.to(String(message.senderId)).emit("messagePinned", payload);
    io.to(String(message.receiverId)).emit("messagePinned", payload);

    return new ApiResponse(
      StatusCodes.OK,
      { message },
      "Message pinned successfully."
    ).send(res);
  }),

  unpinMessage: asyncHandler(async (req, res) => {
    const { messageId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(messageId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid message ID format.");
    }

    const message = await Message.findById(messageId);

    if (!message) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Message not found.");
    }

    if (
      !message.senderId.equals(userId) &&
      !message.receiverId.equals(userId)
    ) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not authorized to unpin this message."
      );
    }

    if (!message.pinned) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Message is not pinned.");
    }

    message.pinned = false;
    await message.save();

    const payload = {
      messageId: message._id,
      unpinned: true,
    };

    io.to(String(message.senderId)).emit("messageUnpinned", payload);
    io.to(String(message.receiverId)).emit("messageUnpinned", payload);

    return new ApiResponse(
      StatusCodes.OK,
      { message },
      "Message unpinned successfully."
    ).send(res);
  }),

  labelMessage: asyncHandler(async (req, res) => {
    const { messageId, label } = req.body;
    const userId = req.user._id;

    if (!messageId || !label) {
      return new ApiError(
        StatusCodes.BAD_REQUEST,
        "Message Id and label are required."
      );
    }

    if (!mongoose.Types.ObjectId.isValid(messageId)) {
      return new ApiResponse(StatusCodes.BAD_REQUEST, "Invalid message ID.");
    }

    if (!validLabels.includes(label)) {
      return new ApiError(StatusCodes.BAD_REQUEST, "Invalid label type.");
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return new ApiError(StatusCodes.NOT_FOUND, "Message not found.");
    }

    if (
      !message.senderId.equals(userId) &&
      !message.receiverId.equals(userId)
    ) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not authorized to label this message."
      );
    }

    const existingLabelIndex = message.labels.findIndex((l) =>
      l.userId.equals(userId)
    );

    if (existingLabelIndex !== -1) {
      message.labels[existingLabelIndex].label = label;
    } else {
      message.labels.push({ userId, label });
    }

    await message.save({ validateBeforeSave: false });

    io.to(userId.toString()).emit("messageLabeled", {
      messageId,
      label,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { message },
      "Label updated successfully."
    ).send(res);
  }),

  removeLabelMessage: asyncHandler(async (req, res) => {
    const { messageId } = req.params;
    const userId = req.user._id;

    if (!messageId) {
      return new ApiError(StatusCodes.BAD_REQUEST, "Message ID is required.");
    }

    if (!mongoose.Types.ObjectId.isValid(messageId)) {
      return new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid message ID format."
      );
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return new ApiError(StatusCodes.NOT_FOUND, "Message not found.");
    }

    if (
      !message.senderId.equals(userId) &&
      !message.receiverId.equals(userId)
    ) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not authorized to label this message."
      );
    }

    const initialLength = message.labels.length;

    message.labels = message.labels.filter(
      (label) => !label.userId.equals(userId)
    );

    if (message.labels.length === initialLength) {
      return new ApiError(
        StatusCodes.BAD_REQUEST,
        "Label not found for this user."
      );
    }

    await message.save({ validateBeforeSave: false });

    io.to(userId.toString()).emit("messageLabelRemoved", { messageId });

    return new ApiResponse(
      StatusCodes.OK,
      { message },
      "Label removed successfully."
    ).send(res);
  }),
};

export default MessageController;
