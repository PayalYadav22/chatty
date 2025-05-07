// ==============================
// External Packages
// ==============================
import { jest } from "@jest/globals";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { StatusCodes } from "http-status-codes";
import crypto from "crypto";
// ==============================
// Utils
// ==============================
import ApiError from "../../utils/apiError.js";

// ==============================
// Mock Modules
// ==============================
jest.unstable_mockModule("../../models/user.model.js", () => ({
  default: {
    findById: jest.fn().mockReturnValue(() => ({
      select: jest.fn().mockResolvedValue(mockUser),
    })),
  },
}));

jest.unstable_mockModule("../../models/tokenBlacklist.model.js", () => ({
  default: {
    find: jest.fn().mockReturnValue(() => ({
      populate: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnValue(mockUser),
    })),
    findOne: jest.fn(),
    findOneAndDelete: jest.fn(),
    countDocuments: jest.fn(),
  },
}));

jest.unstable_mockModule("../../utils/logger.js", () => ({
  logAudit: jest.fn(),
  logActivity: jest.fn(),
  logLoginAttempt: jest.fn(),
  logSession: jest.fn(),
  createAuditLog: jest.fn(),
}));

// ==============================
// Dynamic Imports
// ==============================
const request = (await import("supertest")).default;
const { server } = await import("../../app/app.js");

// ==============================
// Models
// ==============================
const User = (await import("../../models/user.model.js")).default;
const TokenBlacklist = (await import("../../models/tokenBlacklist.model.js"))
  .default;

// ==============================
// Constants
// ==============================
const { logEvents, refreshTokenSecret, accessTokenSecret } = await import(
  "../../constants/constant.js"
);

// ==============================
// Config / Services
// ==============================
const { logAudit, logActivity, logLoginAttempt, logSession } = await import(
  "../../utils/logger.js"
);

const mockUser = {
  _id: new mongoose.Types.ObjectId(),
  email: "test@example.com",
  role: "superAdmin",
  tokenVersion: 1,
  changedPasswordAfter: jest.fn().mockReturnValue(false),
  isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
};

const authenticate = (id, tokenVersion) => {
  return jwt.sign(
    {
      id: mockUser._id,
      role: mockUser.role,
      tokenVersion: mockUser.tokenVersion,
    },
    accessTokenSecret,
    { expiresIn: "1h" }
  );
};

const authHeader = (token) => {
  return { Authorization: `Bearer ${token}` };
};

const hashedToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

describe("TokenBlacklist Controller - Get all token list", () => {
  const endpoint = "/api/v1/auth/token/blacklist";

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return all blacklisted tokens", async () => {
    const mockTokens = [
      {
        _id: new mongoose.Types.ObjectId(),
        token: "hashedToken1",
        createdAt: new Date(),
        userId: mockUser,
      },
    ];

    TokenBlacklist.find.mockReturnValue({
      populate: jest.fn().mockReturnThis(),
      sort: jest.fn().mockResolvedValue(mockTokens),
    });

    jest.spyOn(User, "findById").mockReturnValue({
      select: jest.fn().mockResolvedValue(mockUser),
    });

    const token = authenticate(mockUser._id, mockUser.tokenVersion);

    const res = await request(server).get(endpoint).set(authHeader(token));

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe("Tokens retrieved successfully");
  });
});

describe("TokenBlacklist Controller - Remove blacklisted token", () => {
  const endpoint = "/api/v1/auth/token/blacklist";

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should remove a blacklisted token", async () => {
    const mockUser = {
      _id: new mongoose.Types.ObjectId(),
      email: "test@example.com",
      role: "superAdmin",
      tokenVersion: 1,
    };

    const token = "validAuthToken";
    const hashed = hashedToken(token);
    const mockDeletedToken = {
      _id: new mongoose.Types.ObjectId(),
      token: hashed,
      userId: mockUser._id,
    };

    TokenBlacklist.findOneAndDelete.mockResolvedValue(mockDeletedToken);

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const authToken = authenticate(mockUser._id, mockUser.tokenVersion);

    const res = await request(server)
      .delete(endpoint)
      .set(authHeader(authToken))
      .send({ token });

    expect(TokenBlacklist.findOneAndDelete).toHaveBeenCalledWith({
      token: hashed,
    });
    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe("Token removed from blacklist");
    expect(logAudit).toHaveBeenCalledTimes(2);
    expect(logActivity).not.toHaveBeenCalled();
  });

  it("should throw an error if token is not provided", async () => {
    const authToken = authenticate(mockUser._id, mockUser.tokenVersion);

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .delete(endpoint)
      .set(authHeader(authToken))
      .send({});

    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body).toEqual({
      success: false,
      message: "Token black list remove failed: Token is required.",
      data: { error: "Error" },
    });
    expect(TokenBlacklist.findOneAndDelete).not.toHaveBeenCalled();
    expect(logAudit).toHaveBeenCalledTimes(1);
    expect(logActivity).toHaveBeenCalledTimes(1);
  });

  it("should throw an error if token is not found in blacklist", async () => {
    const token = "nonExistentToken";
    const authToken = authenticate(mockUser._id, mockUser.tokenVersion);
    TokenBlacklist.findOneAndDelete.mockResolvedValue(null);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);
    const res = await request(server)
      .delete(endpoint)
      .set(authHeader(authToken))
      .send({ token });
    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toBe(
      "Token black list remove failed: Token not found in blacklist."
    );
    expect(TokenBlacklist.findOneAndDelete).toHaveBeenCalledWith({
      token: hashedToken(token),
    });
    expect(logAudit).toHaveBeenCalledTimes(1);
    expect(logActivity).toHaveBeenCalledTimes(1);
  });
});

describe("TokenBlacklist Controller - Get blacklist count", () => {
  const endpoint = "/api/v1/auth/token/blacklist/count";

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return the count of blacklisted tokens", async () => {
    const mockCount = 5;

    // Mock TokenBlacklist.countDocuments
    TokenBlacklist.countDocuments.mockResolvedValue(mockCount);

    // Mock createAuditLog
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    // Generate a valid JWT
    const authToken = authenticate(mockUser._id, mockUser.tokenVersion);

    const res = await request(server).get(endpoint).set(authHeader(authToken));

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body).toEqual({
      success: true,
      message: "Tokens count successfully",
      data: mockCount,
    });
    expect(TokenBlacklist.countDocuments).toHaveBeenCalledTimes(1);
  });

  it("should handle errors from countDocuments", async () => {
    TokenBlacklist.countDocuments.mockRejectedValue(
      new Error("Database error")
    );

    const authToken = authenticate(mockUser._id, mockUser.tokenVersion);

    const res = await request(server).get(endpoint).set(authHeader(authToken));

    expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
    expect(res.body.message).toBe("Database error");
  });
});
