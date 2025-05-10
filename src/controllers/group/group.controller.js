// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";
import { StatusCodes } from "http-status-codes";
import { v4 as uuidv4 } from "uuid";

// ==============================
// Models
// ==============================
import Group from "../../models/group.model.js";
import User from "../../models/user.model.js";
import Message from "../../models/message.model.js";
import GroupInvitation from "../../models/groupInvitation.model.js";

// ==============================
// Middlewares
// ==============================
import asyncHandler from "../../middleware/asyncHandler.middleware.js";

// ==============================
// Constants
// ==============================
import {
  privateOptions,
  maxFileSize,
  maxInvites,
  maxUsers,
  maxUpdates,
  validRoles,
} from "../../constants/constant.js";

// ==============================
// Logger
// ==============================
import logger from "../../logger/logger.js";

// ==============================
// Utils
// ==============================
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";

const groupController = {
  createGroup: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const creatorId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(creatorId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid creator Id.");
    }

    const { name, description, privacy } = req.body;

    if (!name || !description || !privacy) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "All fields are required");
    }

    if (name.trim().length < 3 || name.trim().length > 100) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Group name must be 3-100 characters"
      );
    }

    if (description.trim().length < 3 || description.trim().length > 500) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Description must be a string and max 500 characters"
      );
    }

    if (!privateOptions.includes(privacy)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Privacy must be one of: ${privateOptions.join(", ")}`
      );
    }

    const creator = await User.findById(creatorId).select("_id fullName");

    if (!creator) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Creator not found");
    }

    let avatar;
    const localFilePath = req.file?.path;

    if (localFilePath) {
      const mimeType = req.file?.mimetype;
      if (!mimeType?.startsWith("image/")) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Avatar must be an image (jpg, jpeg, png, gif)"
        );
      }
      if (req.file.size > maxFileSize) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Avatar file size must be less than 5MB"
        );
      }

      try {
        avatar = await uploadFileToCloudinary(localFilePath, "image");
        if (!avatar?.url || !avatar?.public_id) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            "Invalid avatar upload response"
          );
        }
      } catch (error) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to upload group avatar"
        );
      }
    }

    let group;
    try {
      group = await Group.create({
        name,
        description,
        privacy,
        creatorId,
        members: [
          {
            userId: creatorId,
            role: "admin",
            joinedAt: new Date(),
          },
        ],
        settings: {
          allowMemberInvites: true,
          muteNotifications: false,
        },
        avatar: avatar
          ? { url: avatar.url, publicId: avatar.public_id }
          : undefined,
      });
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to create group"
      );
    }

    const creatorSocketId = getSocketIdForUser(creatorId.toString());

    if (creatorSocketId) {
      try {
        io.to(creatorSocketId).emit("groupCreated", {
          group: {
            id: group._id,
            name: group.name,
            description: group.description,
            privacy: group.privacy,
            creatorId: group.creatorId,
            members: group.members,
            settings: group.settings,
            avatar: group.avatar,
          },
        });
      } catch (error) {
        logger.error(
          `Socket.IO emit failed for user ${creatorId}: ${error.message}`
        );
      }
    }

    return new ApiResponse(
      StatusCodes.CREATED,
      {
        group: {
          id: group._id,
          name: group.name,
          description: group.description,
          privacy: group.privacy,
          creatorId: group.creatorId,
          members: group.members,
          settings: group.settings,
          avatar: group.avatar,
        },
      },
      "Group created successfully"
    ).send(res);
  }),

  getGroups: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user Id.");
    }

    const { page = 1, limit = 10, privacy, role } = req.query;

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    if (isNaN(pageNum) || pageNum < 1) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid page number");
    }

    if (isNaN(limitNum) || limitNum < 1) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid limit number");
    }

    if (privacy && !privateOptions.includes(privacy)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Privacy must be one of: ${privateOptions.join(", ")}`
      );
    }

    if (role && !["admin", "moderator", "member"].includes(role)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Role must be one of: admin, moderator, member"
      );
    }

    const user = await User.findById(userId).select("_id");

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    const query = {
      $or: [{ creatorId: userId }, { "members.userId": userId }],
    };

    if (privacy) {
      query.privacy = privacy;
    }

    if (role) {
      query["members"] = {
        $elemMatch: {
          userId,
          role,
        },
      };
    }

    const skip = (pageNum - 1) * limitNum;

    let groups, total;

    try {
      [groups, total] = await Promise.all([
        Group.find(query)
          .select("-__v")
          .populate({
            path: "creatorId",
            select: "fullName userName avatar",
          })
          .populate({
            path: "lastMessage",
            select: "content createdAt",
            populate: {
              path: "senderId",
              select: "fullName userName",
            },
          })
          .sort({ updatedAt: -1 })
          .skip(skip)
          .limit(limitNum)
          .lean(),
        Group.countDocuments(query),
      ]);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch groups"
      );
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        groups,
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum),
      },
      "Groups fetched successfully"
    ).send(res);
  }),

  updateGroup: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;

    if (![id, userId].every(mongoose.Types.ObjectId.isValid)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id or userId.");
    }

    let group = await Group.findById(id).select("_id name description privacy");

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const member = group.members.find((m) => m.userId.equals(userId));

    if (!member || member.role !== "admin") {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Only admins can update group details"
      );
    }

    const {
      name,
      description,
      privacy,
      allowMemberInvites,
      muteNotifications,
    } = req.body;

    let updates = {};

    if (name) {
      if (name && name.trim().length < 3) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Group name must be at least 3 characters"
        );
      }
      updates.name = name.trim();
    }

    if (description) {
      if (description && description.trim().length < 3) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Description must be at least 3 characters"
        );
      }
      updates.description = description.trim();
    }

    if (privacy) {
      if (!privateOptions.includes(privacy)) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          `Privacy must be one of: ${privateOptions.join(", ")}`
        );
      }
      updates.privacy = privacy;
    }

    if (allowMemberInvites !== undefined) {
      if (typeof allowMemberInvites !== "boolean") {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "allowMemberInvites must be a boolean"
        );
      }
      updates["settings.allowMemberInvites"] = allowMemberInvites;
    }

    if (muteNotifications !== undefined) {
      if (typeof muteNotifications !== "boolean") {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "muteNotifications must be a boolean"
        );
      }
      updates["settings.muteNotifications"] = muteNotifications;
    }

    let avatar;
    const localFilePath = req.file?.path;

    if (localFilePath) {
      const mimeType = req.file?.mimetype;

      if (!mimeType?.startsWith("image/")) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Avatar must be an image (jpg, jpeg, png, gif)"
        );
      }
      if (req.file.size > maxFileSize) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Avatar file size must be less than 5MB"
        );
      }

      try {
        if (group.avatar?.publicId) {
          await deleteFileToCloudinary(group.avatar.publicId);
        }
        avatar = await uploadFileToCloudinary(localFilePath, "image");
        if (!avatar?.url || !avatar?.public_id) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            "Invalid avatar upload response"
          );
        }
        updates.avatar = { url: avatar.url, publicId: avatar.public_id };
      } catch (error) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to upload group avatar"
        );
      }
    }

    if (Object.keys(updates).length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "No valid fields provided to update"
      );
    }

    try {
      const updatedGroup = await Group.findByIdAndUpdate(
        id,
        { $set: updates },
        { new: true, runValidators: true }
      ).select("-__v");
      if (!updatedGroup) {
        throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
      }
      group = updatedGroup;
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to update group"
      );
    }
    group.members.forEach((member) => {
      const socketId = getSocketIdForUser(member.userId.toString());
      if (socketId) {
        try {
          io.to(socketId).emit("groupUpdated", {
            id: group._id,
            name: group.name,
            description: group.description,
            privacy: group.privacy,
            settings: group.settings,
            avatar: group.avatar,
            updatedAt: group.updatedAt,
          });
        } catch (error) {
          logger.error(
            `Socket.IO emit failed for user ${member.userId}: ${error.message}`
          );
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      group,
      "Group updated successfully"
    ).send(res);
  }),

  deleteGroup: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id.");
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const isCreator = group.creatorId.equals(userId);
    const member = group.members.find((m) => m.userId.equals(userId));
    const isAdmin = member && member.role === "admin";

    if (!isCreator && !isAdmin) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Only admins or the creator can delete the group"
      );
    }

    if (group.avatar?.publicId) {
      try {
        await deleteFileToCloudinary(group.avatar.publicId);
      } catch (error) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to delete group avatar"
        );
      }
    }

    try {
      await Message.deleteMany({ groupId: id });
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        `Failed to delete messages for group ${id}: ${error.message}`
      );
    }

    try {
      await Group.findByIdAndDelete(id);
    } catch (error) {
      logger.error(`Failed to delete group ${id}: ${error.message}`);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to delete group"
      );
    }

    group.members.forEach((member) => {
      const socketId = getSocketIdForUser(member.userId.toString());
      if (socketId) {
        try {
          io.to(socketId).emit("groupDeleted", {
            groupId: id,
            deletedBy: userId,
          });
        } catch (error) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Socket.IO emit failed for user ${member.userId}: ${error.message}`
          );
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { deleted: true, groupId: id },
      "Group deleted successfully"
    ).send(res);
  }),

  joinGroup: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;
    const { inviteCode } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id.");
    }

    try {
      const user = await User.findById(userId).select("_id fullName userName");
      if (!user) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
      }
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to join group"
      );
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    if (group.members.some((m) => m.userId.equals(userId))) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "You are already a member of this group"
      );
    }

    if (group.privacy !== "public" && !inviteCode) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invite code required for this group"
      );
    }

    if (group.privacy !== "public") {
      try {
        const invitation = await GroupInvitation.findOne({
          groupId: id,
          userId,
          status: "pending",
          code: inviteCode,
        });
        if (!invitation) {
          throw new ApiError(
            StatusCodes.FORBIDDEN,
            "Invalid or expired invitation"
          );
        }
        invitation.status = "accepted";
        await invitation.save({ validateBeforeSave: false });
      } catch (error) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to validate invitation"
        );
      }
    }

    const newMember = {
      userId,
      role: "member",
      joinedAt: new Date(),
    };

    try {
      const updatedGroup = await Group.findByIdAndUpdate(
        id,
        { $addToSet: { members: newMember } },
        { new: true, runValidators: true }
      )
        .select("-__v")
        .populate({
          path: "creatorId",
          select: "fullName userName avatar",
        })
        .populate({
          path: "lastMessage",
          select: "content createdAt",
          populate: {
            path: "senderId",
            select: "fullName userName",
          },
        });

      if (!updatedGroup) {
        throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
      }
      group = updatedGroup;
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to join group"
      );
    }

    group.members.forEach((member) => {
      const socketId = getSocketIdForUser(member.userId.toString());
      if (socketId) {
        try {
          io.to(socketId).emit("groupMemberJoined", {
            groupId: group._id,
            userId,
            userName: req.user.userName || "Unknown",
            joinedAt: newMember.joinedAt,
          });
        } catch (error) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Socket.IO emit failed for user ${member.userId}: ${error.message}`
          );
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      group,
      "Successfully joined group"
    ).send(res);
  }),

  leaveGroup: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id.");
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const member = group.members.find((m) => m.userId.equals(userId));
    if (!member) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "You are not a member of this group"
      );
    }

    if (group.creatorId.equals(userId)) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Group creator cannot leave. Delete the group or assign a new creator."
      );
    }

    if (member.role === "admin") {
      const adminCount = group.members.filter((m) => m.role === "admin").length;
      if (adminCount === 1) {
        throw new ApiError(
          StatusCodes.FORBIDDEN,
          "Last admin cannot leave. Assign another admin first."
        );
      }
    }

    try {
      const updatedGroup = await Group.findByIdAndUpdate(
        id,
        { $pull: { members: { userId } } },
        { new: true, runValidators: true }
      );

      if (!updatedGroup) {
        throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
      }

      group = updatedGroup;
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to leave group"
      );
    }

    group.members.forEach((member) => {
      const socketId = getSocketIdForUser(member.userId.toString());
      if (socketId) {
        try {
          io.to(socketId).emit("groupMemberLeft", {
            groupId: group._id,
            userId,
            userName: req.user.userName || "Unknown",
          });
        } catch (error) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Socket.IO emit failed for user ${member.userId}: ${error.message}`
          );
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { left: true, id },
      "Successfully left group"
    ).send(res);
  }),

  getGroupById: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group ID");
    }

    let group;
    try {
      group = await Group.findById(id)
        .select("-__v")
        .populate({
          path: "creatorId",
          select: "fullName userName avatar",
        })
        .populate({
          path: "members.userId",
          select: "fullName userName avatar",
        })
        .populate({
          path: "lastMessage",
          select: "content createdAt",
          populate: {
            path: "senderId",
            select: "fullName userName",
          },
        })
        .lean();
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const isMember = group.members.find((m) => m.userId.equals(userId));
    if (group.privacy !== "public" && !isMember) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Access denied: You are not a member of this group"
      );
    }

    return new ApiResponse(
      StatusCodes.OK,
      group,
      "Group fetched successfully"
    ).send(res);
  }),

  inviteUsers: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;
    const { userIds } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group ID");
    }

    if (!Array.isArray(userIds) || userIds.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "At least one user ID is required"
      );
    }

    if (userIds.length > maxInvites) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Cannot invite more than ${maxInvites} users at once`
      );
    }

    const invalidIds = userIds.filter(
      (id) => !mongoose.Types.ObjectId.isValid(id)
    );

    if (invalidIds.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more user IDs are invalid"
      );
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const member = group.members.find((m) => m.userId.equals(userId));

    if (!member) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not a member of this group"
      );
    }

    if (member.role !== "admin" && !group.settings.allowMemberInvites) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Only admins or members with invite permissions can invite users"
      );
    }

    let validUsers;
    try {
      validUsers = await User.find({ _id: { $in: userIds } }).select("_id");
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to validate users"
      );
    }

    const validUserIds = validUsers.map((u) => u._id.toString());
    const invalidUsers = userIds.filter((id) => !validUserIds.includes(id));

    if (invalidUsers.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more users do not exist"
      );
    }

    const existingMembers = group.members
      .filter((m) => validUserIds.includes(m.userId.toString()))
      .map((m) => m.userId.toString());

    if (existingMembers.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more users are already members of the group"
      );
    }

    let existingInvitations;
    try {
      existingInvitations = await GroupInvitation.find({
        id,
        userId: { $in: validUserIds },
        status: "pending",
      }).select("userId");
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to check existing invitations"
      );
    }

    const alreadyInvited = existingInvitations.map((inv) =>
      inv.userId.toString()
    );
    if (alreadyInvited.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more users have already been invited"
      );
    }

    const invitations = validUserIds.map((userId) => ({
      groupId: id,
      userId,
      invitedBy: req.user._id,
      code: uuidv4(),
      status: "pending",
    }));

    try {
      await GroupInvitation.insertMany(invitations);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to create invitations"
      );
    }

    invitations.forEach((invitation) => {
      const socketId = getSocketIdForUser(invitation.userId.toString());
      if (socketId) {
        try {
          io.to(socketId).emit("groupInvitation", {
            groupId: group._id,
            groupName: group.name,
            invitedBy: req.user.userName || "Unknown",
            inviteCode: invitation.code,
          });
        } catch (error) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Socket.IO emit failed for user ${invitation.userId}: ${error.message}`
          );
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { invited: validUserIds },
      `Successfully invited ${validUserIds.length} users to the group`
    ).send(res);
  }),

  getGroupMessages: asyncHandler(async (req, res) => {
    if (!req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id.");
    }

    const { page = 1, limit = 10 } = req.query;

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    if (isNaN(pageNum) || pageNum < 1) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Page must be a positive integer"
      );
    }

    if (isNaN(limitNum) || limitNum < 1 || limitNum > 10) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Limit must be between 1 and ${10}`
      );
    }

    let group;
    try {
      group = await Group.findById(id).select("members");
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    if (!group.members.some((m) => m.userId.equals(userId))) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not a member of this group"
      );
    }

    let messages, totalMessages;

    try {
      totalMessages = await Message.countDocuments({ groupId: id });
      messages = await Message.find({ groupId: id })
        .select("senderId content createdAt")
        .populate({
          path: "senderId",
          select: "fullName userName avatar",
        })
        .sort({ createdAt: -1 })
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .lean();
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch messages"
      );
    }

    const totalPages = Math.ceil(totalMessages / limitNum);

    return new ApiResponse(
      StatusCodes.OK,
      {
        messages,
        total: totalMessages,
        page: pageNum,
        limit: limitNum,
        totalPages,
        hasNext: pageNum < totalPages,
        hasPrev: pageNum > 1,
      },
      "Messages fetched successfully"
    ).send(res);
  }),

  addUsers: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;
    const { userIds } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id.");
    }

    if (!Array.isArray(userIds) || userIds.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "At least one user Id is required"
      );
    }

    if (userIds.length > maxUsers) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Cannot add more than ${maxUsers} users at once`
      );
    }

    const invalidIds = userIds.filter(
      (id) => !mongoose.Types.ObjectId.isValid(id)
    );
    if (invalidIds.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more user IDs are invalid"
      );
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const member = group.members.find((m) => m.userId.equals(userId));
    if (!member) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not a member of this group"
      );
    }

    if (member.role !== "admin") {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Only admins can add users to the group"
      );
    }

    let validUsers;
    try {
      validUsers = await User.find({ _id: { $in: userIds } }).select(
        "_id userName"
      );
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to validate users"
      );
    }

    const validUserIds = validUsers.map((u) => u._id.toString());
    const invalidUsers = userIds.filter((id) => !validUserIds.includes(id));
    if (invalidUsers.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more users do not exist"
      );
    }

    const existingMembers = group.members
      .filter((m) => validUserIds.includes(m.userId.toString()))
      .map((m) => m.userId.toString());
    if (existingMembers.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more users are already members of the group"
      );
    }

    const newMembers = validUserIds.map((userId) => ({
      userId,
      role: "member",
      joinedAt: new Date(),
    }));

    try {
      group.members.push(...newMembers);
      await group.save({ validateBeforeSave: false });
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to add users to group"
      );
    }

    validUserIds.forEach((userId) => {
      const socketId = getSocketIdForUser(userId);
      if (socketId) {
        try {
          io.to(socketId).emit("addedToGroup", {
            groupId: group._id,
            groupName: group.name,
            addedBy: req.user.userName || "Unknown",
            addedUsers: validUsers.map((u) => ({
              userId: u._id,
              userName: u.userName,
            })),
          });
        } catch (error) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Socket.IO emit failed for user ${userId}: ${error.message}`
          );
        }
      }
    });

    group.members.forEach((member) => {
      if (!validUserIds.includes(member.userId.toString())) {
        const socketId = getSocketIdForUser(member.userId.toString());
        if (socketId) {
          try {
            io.to(socketId).emit("newGroupMembers", {
              groupId: group._id,
              groupName: group.name,
              addedBy: req.user.userName || "Unknown",
              addedUsers: validUsers.map((u) => ({
                userId: u._id,
                userName: u.userName,
              })),
            });
          } catch (error) {
            logger.warn(
              `Socket.IO emit failed for member ${member.userId}: ${error.message}`
            );
          }
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { added: validUserIds },
      `Successfully added ${validUserIds.length} users to the group`
    ).send(res);
  }),

  removeUsers: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;
    const { userIds } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id.");
    }

    if (!Array.isArray(userIds) || userIds.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "At least one user ID is required"
      );
    }

    if (userIds.length > maxUsers) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Cannot remove more than ${maxUsers} users at once`
      );
    }

    const invalidIds = userIds.filter(
      (id) => !mongoose.Types.ObjectId.isValid(id)
    );
    if (invalidIds.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more user IDs are invalid"
      );
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const member = group.members.find((m) => m.userId.equals(userId));

    if (!member) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not a member of this group"
      );
    }

    if (member.role !== "admin") {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Only admins can remove users from the group"
      );
    }

    const memberIds = group.members.map((m) => m.userId.toString());
    const nonMembers = userIds.filter((id) => !memberIds.includes(id));
    if (nonMembers.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more users are not members of the group"
      );
    }

    const creatorId = group.creatorId.toString();
    if (userIds.includes(creatorId)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Cannot remove the group creator"
      );
    }

    const admins = group.members.filter((m) => m.role === "admin");
    const adminsToRemove = userIds.filter((id) =>
      admins.some((admin) => admin.userId.toString() === id)
    );
    if (admins.length <= adminsToRemove.length) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Cannot remove the last admin of the group"
      );
    }

    try {
      await Group.findByIdAndUpdate(
        id,
        { $pull: { members: { userId: { $in: userIds } } } },
        { new: true, runValidators: true }
      );
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to remove users from group"
      );
    }

    let removedUsers;
    try {
      removedUsers = await User.find({ _id: { $in: userIds } }).select(
        "_id userName"
      );
    } catch (error) {
      removedUsers = userIds.map((id) => ({ _id: id, userName: "Unknown" }));
    }

    const payload = {
      groupId: group._id,
      groupName: group.name,
      removedBy: req.user.userName || "Unknown",
      removedUsers: removedUsers.map((u) => ({
        userId: u._id,
        userName: u.userName,
      })),
    };

    userIds.forEach((userId) => {
      const socketId = getSocketIdForUser(userId);
      if (socketId) {
        try {
          io.to(socketId).emit("removedFromGroup", payload);
        } catch (error) {
          logger.warn(
            `Socket.IO emit failed for user ${userId}: ${error.message}`
          );
        }
      }
    });

    group.members.forEach((member) => {
      if (!userIds.includes(member.userId.toString())) {
        const socketId = getSocketIdForUser(member.userId.toString());
        if (socketId) {
          try {
            io.to(socketId).emit("groupMembersRemoved", payload);
          } catch (error) {
            logger.warn(
              `Socket.IO emit failed for member ${member.userId}: ${error.message}`
            );
          }
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { removed: userIds },
      `Successfully removed ${userIds.length} users from the group`
    ).send(res);
  }),

  updateGroupRoles: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;
    const { updates } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group ID");
    }

    if (!Array.isArray(updates) || updates.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "At least one role update is required"
      );
    }

    if (updates.length > maxUpdates) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Cannot update more than ${maxUpdates} roles at once`
      );
    }

    for (const update of updates) {
      if (!mongoose.Types.ObjectId.isValid(update.userId)) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          `Invalid user ID: ${update.userId}`
        );
      }
      if (!validRoles.includes(update.role)) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          `Invalid role: ${update.role}. Must be one of ${validRoles.join(
            ", "
          )}`
        );
      }
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const member = group.members.find((m) => m.userId.equals(userId));
    if (!member) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not a member of this group"
      );
    }

    if (member.role !== "admin") {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Only admins can update group roles"
      );
    }

    const memberIds = group.members.map((m) => m.userId.toString());
    const updateUserIds = updates.map((u) => u.userId);
    const nonMembers = updateUserIds.filter((id) => !memberIds.includes(id));
    if (nonMembers.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "One or more users are not members of the group"
      );
    }

    const creatorId = group.creatorId.toString();
    const creatorUpdates = updates.filter((u) => u.userId === creatorId);
    if (creatorUpdates.length > 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Cannot update the group creator's role"
      );
    }

    const admins = group.members.filter((m) => m.role === "admin");
    const adminDemotions = updates.filter(
      (u) =>
        admins.some((admin) => admin.userId.toString() === u.userId) &&
        u.role !== "admin"
    );

    if (admins.length <= adminDemotions.length) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Cannot demote the last admin of the group"
      );
    }

    try {
      for (const update of updates) {
        await Group.findOneAndUpdate(
          { _id: id, "members.userId": update.userId },
          { $set: { "members.$.role": update.role } },
          { runValidators: true }
        );
      }
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to update group roles"
      );
    }

    let updatedUsers;
    try {
      updatedUsers = await User.find({ _id: { $in: updateUserIds } }).select(
        "_id userName"
      );
    } catch (error) {
      updatedUsers = updateUserIds.map((id) => ({
        _id: id,
        userName: "Unknown",
      }));
    }

    const payload = {
      groupId: group._id,
      groupName: group.name,
      updatedBy: req.user.userName || "Unknown",
      updatedRoles: updates.map((u) => ({
        userId: u.userId,
        userName:
          updatedUsers.find((user) => user._id.toString() === u.userId)
            ?.userName || "Unknown",
        role: u.role,
      })),
    };

    updateUserIds.forEach((userId) => {
      const socketId = getSocketIdForUser(userId);
      if (socketId) {
        try {
          io.to(socketId).emit("groupRoleUpdated", payload);
        } catch (error) {
          throw new ApiError(
            `Socket.IO emit failed for user ${userId}: ${error.message}`
          );
        }
      }
    });

    group.members.forEach((member) => {
      const socketId = getSocketIdForUser(member.userId.toString());
      if (socketId) {
        try {
          io.to(socketId).emit("groupRolesUpdated", payload);
        } catch (error) {
          throw new ApiError(
            `Socket.IO emit failed for member ${member.userId}: ${error.message}`
          );
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { updated: updates },
      `Successfully updated ${updates.length} group roles`
    ).send(res);
  }),

  updateGroupSettings: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;
    const settings = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id.");
    }

    if (!settings || Object.keys(settings).length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "At least one setting must be provided"
      );
    }

    for (const [key, value] of Object.entries(settings)) {
      if (!validSettings.includes(key)) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          `Invalid setting: ${key}. Must be one of ${validSettings.join(", ")}`
        );
      }
      if (typeof value !== "boolean") {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          `Setting ${key} must be a boolean`
        );
      }
    }

    let group;

    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    const member = group.members.find((m) => m.userId.equals(userId));
    if (!member) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not a member of this group"
      );
    }

    if (member.role !== "admin") {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Only admins can update group settings"
      );
    }

    const updateFields = {};
    if (settings.allowMemberInvites !== undefined) {
      updateFields["settings.allowMemberInvites"] = settings.allowMemberInvites;
    }
    if (settings.muteNotifications !== undefined) {
      updateFields["settings.muteNotifications"] = settings.muteNotifications;
    }

    let updatedGroup;
    try {
      updatedGroup = await Group.findByIdAndUpdate(
        id,
        { $set: updateFields },
        { new: true, runValidators: true }
      ).select("settings");
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to update group settings"
      );
    }

    const payload = {
      groupId: group._id,
      groupName: group.name,
      updatedBy: req.user.userName || "Unknown",
      settings: updatedGroup.settings,
    };

    group.members.forEach((member) => {
      const socketId = getSocketIdForUser(member.userId.toString());
      if (socketId) {
        try {
          io.to(socketId).emit("groupSettingsUpdated", payload);
        } catch (error) {
          throw new ApiError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Socket.IO emit failed for member ${member.userId}: ${error.message}`
          );
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { settings: updatedGroup.settings },
      "Group settings updated successfully"
    ).send(res);
  }),

  sendGroupMessage: asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user._id;
    const { id } = req.params;
    const { content } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid group Id");
    }

    if (!content || content.trim().length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Message content is required"
      );
    }

    if (content.trim().length > 2000) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Message cannot exceed 2000 characters"
      );
    }

    let group;
    try {
      group = await Group.findById(id);
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to fetch group"
      );
    }

    if (!group) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Group not found");
    }

    if (!group.members.some((m) => m.userId.equals(userId))) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not a member of this group"
      );
    }

    let message;
    try {
      message = await Message.create({
        groupId: id,
        senderId: userId,
        content: content.trim(),
      });
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to send message"
      );
    }

    try {
      await Group.findByIdAndUpdate(
        id,
        { $set: { lastMessage: message._id } },
        { runValidators: true }
      );
    } catch (error) {
      await Message.deleteOne({ _id: message._id });
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to update group"
      );
    }

    try {
      message = await Message.findById(message._id)
        .populate({
          path: "senderId",
          select: "fullName userName avatar",
        })
        .lean();
    } catch (error) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        `Failed to populate sender details for message ${message._id}: ${error.message}`
      );
    }

    const payload = {
      groupId: group._id,
      groupName: group.name,
      message: {
        _id: message._id,
        content: message.content,
        senderId: message.senderId?._id || userId,
        sender: {
          fullName: message.senderId?.fullName || "Unknown",
          userName: message.senderId?.userName || "Unknown",
          avatar: message.senderId?.avatar || {},
        },
        createdAt: message.createdAt,
      },
    };

    group.members.forEach((member) => {
      if (!group.settings.muteNotifications) {
        const socketId = getSocketIdForUser(member.userId.toString());
        if (socketId) {
          try {
            io.to(socketId).emit("newGroupMessage", payload);
          } catch (error) {
            throw new ApiError(
              StatusCodes.INTERNAL_SERVER_ERROR,
              `Socket.IO emit failed for member ${member.userId}: ${error.message}`
            );
          }
        }
      }
    });

    return new ApiResponse(
      StatusCodes.OK,
      { message: payload.message },
      "Message sent successfully"
    ).send(res);
  }),
};

export default groupController;
