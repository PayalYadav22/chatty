// ==============================
// External Packages
// ==============================
import { jest } from "@jest/globals";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { StatusCodes } from "http-status-codes";

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
const Session = (await import("../../models/session.model.js")).default;
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

const authenticate = (id) => {
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

describe("Session Controller - Create Session", () => {
  const endpoint = "/api/v1/auth/session";
  it("should create a session when refresh token is provided", async () => {
    const mockUser = {
      _id: new mongoose.Types.ObjectId(),
      email: "test@example.com",
      role: "superAdmin",
      tokenVersion: 1,
      changedPasswordAfter: jest.fn().mockReturnValue(false),
      isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
    };
    const mockSession = {
      _id: "123",
      deviceFingerprint: "abc",
      expiresAt: new Date(),
    };
    const mockTokens = [
      {
        _id: new mongoose.Types.ObjectId(),
        token: "hashedToken1",
        createdAt: new Date(),
        userId: mockUser,
      },
    ];

    TokenBlacklist.findOne.mockResolvedValue(null);

    jest.spyOn(User, "findById").mockReturnValue({
      select: jest.fn().mockResolvedValue(mockUser),
    });

    jest.spyOn(Session, "create").mockResolvedValue({
      _id: "123",
      deviceFingerprint: "abc",
      expiresAt: new Date(),
    });

    const token = authenticate(mockUser._id);

    logSession.mockResolvedValue(mockSession);

    const res = await request(server)
      .post(endpoint)
      .set(authHeader(token))
      .send({ refreshToken: "valid-token" });

    expect(res.status).toBe(StatusCodes.CREATED);
    expect(res.body.message).toBe(
      "Session created successfully: New session created for user."
    );
  }, 10000);
});

describe("Session Controller - Get Sessions For User", () => {
  const endpoint = "/api/v1/auth/session";
  it("should return active sessions for the authenticated user", async () => {
    const mockUser = {
      _id: new mongoose.Types.ObjectId(),
      email: "test@example.com",
    };

    const mockSessions = [
      {
        _id: new mongoose.Types.ObjectId(),
        userId: mockUser._id,
        deviceFingerprint: "abc123",
        isValid: true,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
    ];
    jest.spyOn(Session, "find").mockReturnValueOnce({
      sort: jest.fn().mockReturnValue({
        select: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue(mockSessions),
        }),
      }),
    });

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);
    const token = authenticate(mockUser._id);
    const res = await request(server).get(endpoint).set(authHeader(token));

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toBe("Active sessions retrieved successfully.");
    expect(res.body.data.sessions).toHaveLength(1);
    expect(res.body.data.sessions[0].userId).toBe(mockUser._id.toString());
  }, 10000);
});

describe("Session Controller - Get Sessions By Id", () => {
  const endpoint = "/api/v1/auth/session";

  const mockUser = {
    _id: new mongoose.Types.ObjectId(),
    email: "test@example.com",
  };

  const sessionId = new mongoose.Types.ObjectId();

  const mockSession = {
    _id: sessionId,
    userId: mockUser._id,
    deviceFingerprint: "device123",
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  };

  const token = authenticate(mockUser._id);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return session details if valid ID and session exists", async () => {
    jest.spyOn(Session, "findOne").mockReturnValueOnce({
      select: jest.fn().mockReturnValueOnce({
        lean: jest.fn().mockResolvedValueOnce(mockSession),
      }),
    });

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .get(`${endpoint}/${sessionId}`)
      .set(authHeader(token));

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toBe(
      "Session view successful: Session details retrieved successfully."
    );
    expect(res.body.data.session._id).toBe(sessionId.toString());
  });

  it("should return 400 for invalid session ID", async () => {
    const res = await request(server)
      .get(`${endpoint}/invalid-id`)
      .set(authHeader(token));
    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toMatch("Invalid session ID.");
  });

  it("should return 404 if session not found", async () => {
    jest.spyOn(Session, "findOne").mockReturnValueOnce({
      select: jest.fn().mockReturnValueOnce({
        lean: jest.fn().mockResolvedValueOnce(null),
      }),
    });
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .get(`${endpoint}/${sessionId}`)
      .set(authHeader(token));

    expect(res.status).toBe(StatusCodes.NOT_FOUND);
    expect(res.body.message).toBe(
      "Session view failed: Session not found or does not belong to the user."
    );
  });
});

describe("Session Controller - Invalidate Session", () => {
  const endpoint = "/api/v1/auth/session/invalidate";
  const mockUser = {
    _id: new mongoose.Types.ObjectId(),
    email: "test@example.com",
  };
  const token = authenticate(mockUser._id);
  it("should return 400 for invalid session ID", async () => {
    const res = await request(server)
      .get(`${endpoint}/invalid-id`)
      .set(authHeader(token));

    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toBe("Invalid session ID.");
  });

  it("should return 404 if session not found", async () => {
    Session.findOne.mockResolvedValue(null);

    const res = await request(server)
      .get(`${endpoint}/681b360e0d5dd0395157b8e5`)
      .set(authHeader(token));

    expect(res.status).toBe(StatusCodes.NOT_FOUND);
    expect(res.body.message).toBe(
      "Session invalidate failed: Session not found or already invalid."
    );
  });

  it("should invalidate session and return success", async () => {
    const mockSession = {
      _id: "681b360e0d5dd0395157b8e5",
      userId: "681b360e0d5dd0395157b8e4",
      isValid: true,
      save: jest.fn().mockResolvedValue(true),
    };
    Session.findOne.mockResolvedValue(mockSession);

    const res = await request(server)
      .get(`${endpoint}/681b360e0d5dd0395157b8e5`)
      .set(authHeader(token));

    expect(mockSession.save).toHaveBeenCalled();
    expect(mockSession.isValid).toBe(false);

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toMatch(
      "Session invalidated successfully: Session marked as invalid."
    );
  });
});

describe("Session Controller - Delete Session", () => {
  const endpoint = "/api/v1/auth/session";
  const mockUser = {
    _id: new mongoose.Types.ObjectId(),
    email: "test@example.com",
  };
  const token = authenticate(mockUser._id);
  beforeEach(() => jest.clearAllMocks());

  it("should return 400 for invalid ObjectId", async () => {
    const res = await request(server)
      .delete(`${endpoint}/invalid-id`)
      .set(authHeader(token));
    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toBe("Invalid session Id.");
  });

  it("should return 404 if session not found or unauthorized", async () => {
    Session.findOne.mockResolvedValue(null);

    const res = await request(server)
      .delete(`${endpoint}/681b360e0d5dd0395157b8e5`)
      .set(authHeader(token));

    expect(res.status).toBe(StatusCodes.NOT_FOUND);
    expect(res.body.message).toBe("Session delete failed: Session not found.");
  });

  it("should delete session and return 200", async () => {
    const mockSession = {
      _id: "681b360e0d5dd0395157b8e5",
      userId: "681b360e0d5dd0395157b8e4",
    };

    jest.spyOn(Session, "findOne").mockResolvedValue(mockSession);
    jest.spyOn(Session, "findByIdAndDelete").mockResolvedValue({});

    const res = await request(server)
      .delete(`${endpoint}/${mockSession._id}`)
      .set(authHeader(token));

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe("Session deleted successfully.");
  });
});

describe("Session Controller - Get Active Session Count", () => {
  const endpoint = "/api/v1/auth/session/active/count";
  const mockUser = {
    _id: new mongoose.Types.ObjectId(),
    email: "test@example.com",
  };
  const token = authenticate(mockUser._id);
  beforeEach(() => {
    jest.clearAllMocks();
  });
  it("should return 200 with session count", async () => {
    const res = await request(server).get(endpoint).set(authHeader(token));
    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe(
      "Session retrieve successful: Active session count retrieved successfully."
    );
  });
  it("should return 400 if DB throws error", async () => {
    jest
      .spyOn(Session, "countDocuments")
      .mockRejectedValue(new Error("DB Error"));

    const res = await request(server).get(endpoint).set(authHeader(token));
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch("Session retrieve failed: DB Error");
  });
});

describe("Session Controller - Logout All Sessions", () => {
  const endpoint = "/api/v1/auth/session/logout/all";
  const mockUser = {
    _id: new mongoose.Types.ObjectId(),
    email: "test@example.com",
  };
  const token = authenticate(mockUser._id);
  beforeEach(() => {
    jest.clearAllMocks();
  });
  it("should logout all sessions and return 200", async () => {
    Session.updateMany = jest.fn().mockResolvedValue({ modifiedCount: 2 });
    Session.deleteMany = jest.fn().mockResolvedValue({ deletedCount: 5 });

    const res = await request(server).delete(endpoint).set(authHeader(token));

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe(
      "Session logout successful: All sessions have been logged out successfully."
    );
  });

  it("should handle DB errors gracefully", async () => {
    jest
      .spyOn(Session, "updateMany")
      .mockRejectedValue(new Error("DB update failed"));

    const res = await request(server).delete(endpoint).set(authHeader(token));

    expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
    expect(res.body.message).toBe("DB update failed");

    expect(logAudit).not.toHaveBeenCalled();
    expect(logActivity).not.toHaveBeenCalled();
  });
});

describe("Session Controller - Cleanup Expired Sessions", () => {
  const endpoint = "/api/v1/auth/session/cleanup/expired";
  const mockUser = {
    _id: new mongoose.Types.ObjectId(),
    email: "test@example.com",
  };
  const token = authenticate(mockUser._id);
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should delete expired sessions and return success", async () => {
    jest.spyOn(Session, "deleteMany").mockResolvedValue({ deletedCount: 3 });
    const res = await request(server).delete(endpoint).set(authHeader(token));
    expect(Session.deleteMany).toHaveBeenCalledWith({
      expiresAt: {
        $lte: expect.any(Date),
      },
    });
    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe("Expired sessions cleaned up successfully.");
  });

  it("should handle DB errors and return 500", async () => {
    jest.spyOn(Session, "deleteMany").mockRejectedValue(new Error("DB Error"));
    const res = await request(server).delete(endpoint).set(authHeader(token));
    expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
    expect(res.body.message).toBe("DB Error");
  });
});
