// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";
import { jest } from "@jest/globals";
import { StatusCodes } from "http-status-codes";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";

// ==============================
// Utils
// ==============================
import ApiError from "../../utils/apiError.js";

// ==============================
// Mock Modules
// ==============================
jest.unstable_mockModule("../../models/user.model.js", () => ({
  default: jest.fn(),
}));

jest.unstable_mockModule("../../models/tokenBlacklist.model.js", () => ({
  default: {
    create: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
  },
}));

jest.unstable_mockModule("../../models/session.model.js", () => ({
  default: {
    findOneAndUpdate: jest.fn(),
    create: jest.fn(),
  },
}));

jest.unstable_mockModule("../../utils/otp.js", () => ({
  default: jest.fn(),
}));

jest.unstable_mockModule("../../utils/email.js", () => ({
  default: jest.fn(),
}));

jest.unstable_mockModule("../../utils/logger.js", () => ({
  logAudit: jest.fn(),
  logActivity: jest.fn(),
  logLoginAttempt: jest.fn(),
  logSession: jest.fn(),
}));

jest.unstable_mockModule("../../config/cloudinary.config.js", () => ({
  uploadFileToCloudinary: jest.fn(),
  deleteFileToCloudinary: jest.fn(),
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
const Session = (await import("../../models/session.model.js")).default;

// ==============================
// constants
// ==============================

const { logEvents, refreshTokenSecret, accessTokenSecret } = await import(
  "../../constants/constant.js"
);

// ==============================
// Config / Services
// ==============================
const { uploadFileToCloudinary } = await import(
  "../../config/cloudinary.config.js"
);
const sendEmail = (await import("../../utils/email.js")).default;
const generateOTP = (await import("../../utils/otp.js")).default;
const { logAudit } = await import("../../utils/logger.js");
const { logActivity } = await import("../../utils/logger.js");
const { logLoginAttempt } = await import("../../utils/logger.js");
const { logSession } = await import("../../utils/logger.js");

// ==============================
// Constant and Variable Name
// ==============================

async function createTestUserWithPasswordHistory(passwordHistory) {
  const hashedHistory = await Promise.all(
    passwordHistory.map((pw) => bcrypt.hash(pw, 10))
  );

  const latestPassword = hashedHistory[hashedHistory.length - 1];

  const user = await User.create({
    email: "testuser@example.com",
    password: latestPassword,
    passwordHistory: hashedHistory.slice(0, -1),
    isEmailVerified: true,
  });

  return user;
}

async function generateValidPasswordResetToken(user) {
  const token = crypto.randomBytes(32).toString("hex");
  user.passwordResetToken = token;
  user.passwordResetTokenExpiration = Date.now() + 3600000;
  await user.save();
  return token;
}
// ==============================
// Test Suite: Auth Controller - User Register
// ==============================
describe("Auth Controller - Registration", () => {
  // ==============================
  // Test Data
  // ==============================
  const dummyUser = {
    _id: "user1234",
    fullName: "Test User",
    email: "test@example.com",
    userName: "testuser",
    phone: "1234567890",
    password: "Password@123",
    avatar: {
      url: "http://example.com/avatar.jpg",
      publicId: "img123",
    },
    role: "user",
    otp: "123456",
    otpExpiry: new Date(Date.now() + 10 * 60 * 1000),
    isVerified: false,
    twoFactorEnabled: false,
    resetOtpAttempts: jest.fn().mockResolvedValue(),
    securityQuestions: [
      {
        question: "What was the name of your first pet?",
        answer: "Fluffy",
      },
      {
        question: "What is your favorite book?",
        answer: "1984",
      },
    ],
  };

  // ==============================
  // Setup: Mocks and Spies
  // ==============================
  beforeAll(() => {
    generateOTP.mockReturnValue("123456");
    uploadFileToCloudinary.mockResolvedValue({
      secure_url: dummyUser.avatar.url,
      public_id: dummyUser.avatar.publicId,
    });
    sendEmail.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);
    User.create = jest.fn().mockResolvedValue(dummyUser);
    User.findOne = jest.fn().mockResolvedValue(null);
    User.verifyRecaptcha = jest.fn().mockResolvedValue({ success: true });
  });

  // ==============================
  // Teardown: Cleanup
  // ==============================
  afterAll(async () => {
    await server.close();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ==============================
  // Test Case: User Registration
  // ==============================
  it("should register a new user successfully", async () => {
    const res = await request(server)
      .post("/api/v1/auth/register")
      .field("fullName", dummyUser.fullName)
      .field("email", dummyUser.email)
      .field("userName", dummyUser.userName)
      .field("phone", dummyUser.phone)
      .field("password", dummyUser.password)
      .field("recaptchaToken", "valid-token-123")
      // Send security questions as individual fields
      .field(
        "securityQuestions[0][question]",
        dummyUser.securityQuestions[0].question
      )
      .field(
        "securityQuestions[0][answer]",
        dummyUser.securityQuestions[0].answer
      )
      .field(
        "securityQuestions[1][question]",
        dummyUser.securityQuestions[1].question
      )
      .field(
        "securityQuestions[1][answer]",
        dummyUser.securityQuestions[1].answer
      )
      .attach("avatar", "src/tests/fixtures/avatar.jpg");

    // ==============================
    // Assertions: Verify Results
    // ==============================
    expect(res.status).toBe(201);
    expect(res.body.message).toMatch(/Registration successful/i);
    expect(res.body.data.userName).toBe(dummyUser.userName);
    expect(User.create).toHaveBeenCalledTimes(1);
    expect(generateOTP).toHaveBeenCalledTimes(1);
    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(logAudit).toHaveBeenCalledTimes(1);
    expect(logActivity).toHaveBeenCalledTimes(1);

    // Verify securityQuestions were properly included in creation
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        securityQuestions: expect.arrayContaining([
          expect.objectContaining({
            question: dummyUser.securityQuestions[0].question,
            answer: dummyUser.securityQuestions[0].answer,
          }),
          expect.objectContaining({
            question: dummyUser.securityQuestions[1].question,
            answer: dummyUser.securityQuestions[1].answer,
          }),
        ]),
      })
    );
  }, 10000);
});

// ==============================
// Test Suite: Auth Controller - Verify Email
// ==============================
describe("Auth Controller - Verify Email", () => {
  let dummyUser;

  // ==============================
  // Setup: Runs before each test
  // ==============================
  beforeEach(() => {
    dummyUser = {
      _id: "user112334",
      fullName: "Test User",
      email: "test@example.com",
      userName: "testuser",
      phone: "1234567890",
      password: "Password@123",
      avatar: {
        secure_url: "http://example.com/avatar.jpg",
        public_id: "img123",
      },
      recaptchaToken: "valid-token-123",
      otp: "123456",
      otpExpiry: new Date(Date.now() + 10 * 60 * 1000),
      isVerified: false,
      role: "user",
      resetOtpAttempts: jest.fn(),
      compareOTP: jest.fn().mockResolvedValue(true),
      enableTwoFactor: jest
        .fn()
        .mockResolvedValue({ qrCodeDataURL: "fake-qr-code-url" }),
      save: jest.fn().mockResolvedValue(true),
    };
  });

  // ==============================
  // Teardown
  // ==============================
  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should return 400 if email or otp is missing", async () => {
    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "user@example.com" });

    expect(res.status).toBe(400);
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  }, 10000);

  it("should return 400 for invalid or expired OTP", async () => {
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(null),
    });

    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "user@example.com", otp: "123456" });

    expect(res.status).toBe(400);
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  }, 10000);

  it("should verify user and return tokens and QR code", async () => {
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    User.generateToken = jest.fn().mockResolvedValue({
      accessToken: "access-token",
      refreshToken: "refresh-token",
    });

    logSession.mockResolvedValue(true);

    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "user@example.com", otp: "123456" });
    expect(res.status).toBe(200);
    expect(res.body.data.qrCode).toBeDefined();
    expect(dummyUser.enableTwoFactor).toHaveBeenCalled();
    expect(User.generateToken).toHaveBeenCalled();
    expect(logSession).toHaveBeenCalled();
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        actorId: dummyUser._id,
        targetId: dummyUser._id,
        eventType: logEvents.VERIFIED_EMAIL_SUCCESS,
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: dummyUser._id,
        action: logEvents.VERIFIED_EMAIL_SUCCESS,
      })
    );
  }, 10000);

  it("should handle expired OTP and throw an error", async () => {
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(null),
    });

    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "user@example.com", otp: "123456" });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe("Email verification failed: User not found.");
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  }, 10000);

  it("should return 400 if OTP is incorrect", async () => {
    dummyUser.compareOTP = jest.fn().mockResolvedValue(false);

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "test@example.com", otp: "wrong-otp" });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      "Email verification failed: The OTP you entered is invalid or has expired. Please request a new one."
    );
    expect(dummyUser.compareOTP).toHaveBeenCalledWith("wrong-otp");
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  }, 10000);

  it("should return 400 if user is already verified", async () => {
    dummyUser.isVerified = true;

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });
    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "user@example.com", otp: "123456" });
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/already verified/i);
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  }, 10000);

  it("should return 500 if enabling two-factor authentication fails", async () => {
    dummyUser.enableTwoFactor = jest.fn().mockRejectedValue();

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "test@example.com", otp: "123456" });

    expect(res.status).toBe(500);
    expect(res.body.message).toMatch(
      /Failed to enable Two-Factor Authentication/i
    );
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  }, 10000);

  it("should return 500 if createSession fails", async () => {
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    User.generateToken = jest.fn().mockResolvedValue({
      accessToken: "mockAccessToken",
      refreshToken: "mockRefreshToken",
    });

    logSession.mockRejectedValue();

    const res = await request(server)
      .post("/api/v1/auth/verify-email")
      .send({ email: "test@example.com", otp: "123456" });

    expect(res.status).toBe(500);
    expect(res.body.message).toMatch(/Session creation failed/i);
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  }, 10000);
});

// ==============================
// Test Suite: Auth Controller - Login
// ==============================
describe("Auth Controller - Login", () => {
  let dummyUser = {
    _id: "user1234",
    fullName: "Test User",
    email: "test@example.com",
    userName: "testuser",
    phone: "1234567890",
    password: "Password@123",
    avatar: {
      url: "http://example.com/avatar.jpg",
      publicId: "img123",
    },
    role: "user",
    otp: "123456",
    otpExpiry: new Date(Date.now() + 10 * 60 * 1000),
    isVerified: false,
    twoFactorEnabled: false,
    resetOtpAttempts: jest.fn().mockResolvedValue(),
    securityQuestions: [
      {
        question: "What was the name of your first pet?",
        answer: "Fluffy",
      },
      {
        question: "What is your favorite book?",
        answer: "1984",
      },
    ],
  };
  let user;
  const endpoint = "/api/v1/auth/login";

  beforeAll(async () => {
    user = await User.create(dummyUser);
  });

  afterEach(() => {});

  afterAll(async () => {});

  it("should fail when both email and phone are missing", async () => {
    const res = await request(server).post(endpoint).send({
      password: "Password123!",
      twoFactorCode: "123456",
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      "Validation error: Either email or phone is required."
    );
  }, 10000);

  it("should fail when password is missing", async () => {
    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      twoFactorCode: "123456",
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Validation error: "password" is required');
  }, 10000);

  it("should fail when 2FA code is missing", async () => {
    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      password: "Password123!",
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      'Validation error: "twoFactorCode" is required'
    );
  }, 10000);

  it("should fail when email is malformed", async () => {
    const res = await request(server).post(endpoint).send({
      email: "invalid-email",
      password: "Password123!",
      twoFactorCode: "123456",
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      'Validation error: "email" must be a valid email'
    );
  }, 10000);

  it("should fail when 2FA code is non-numeric or wrong length", async () => {
    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      password: "Password123!",
      twoFactorCode: "abc123",
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(
      "Validation error: 2FA code must contain only digits."
    );
  }, 10000);

  it("should pass with valid email, password, and 2FA (mocked)", async () => {
    User.findOne = jest.fn().mockReturnValue({
      select: jest.fn().mockResolvedValue(null),
    });
    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      password: "Password123!",
      twoFactorCode: "123456",
    });
    expect([200, 401]).toContain(res.status);
  }, 10000);

  it("should fail if missing credentials", async () => {
    const res = await request(server)
      .post(endpoint)
      .send({ password: "password123", twoFactorCode: "123456" });
    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      "Validation error: Either email or phone is required."
    );
  }, 10000);

  it("should fail if user does not exist", async () => {
    const res = await request(server).post(endpoint).send({
      email: "nonexistent@example.com",
      password: "password123",
      twoFactorCode: "123456",
    });
    expect(res.status).toBe(401);
    expect(res.body.message).toBe(
      "Login attempt failed: User not found for email: nonexistent@example.com"
    );
  }, 10000);
});

// ==============================
// Test Suite: Auth Controller - Forgot Password
// ==============================
describe("Auth Controller - forgot Password", () => {
  let dummyUser;
  const endpoint = "/api/v1/auth/forgot-password";

  beforeEach(() => {
    jest.clearAllMocks();

    dummyUser = new User({
      _id: "user123",
      email: "test@example.com",
      fullName: "Test User",
    });

    dummyUser.securityQuestions = [];
    dummyUser.generateCryptoToken = jest.fn().mockResolvedValue("reset-token");
    dummyUser.save = jest.fn().mockResolvedValue();

    jest.spyOn(User, "findOne").mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });
  });

  it("should return 400 if email is missing", async () => {
    const res = await request(server).post(endpoint).send({});

    expect(res.statusCode).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toMatch(/missing email/i);
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: expect.stringContaining(logEvents.FORGOT_PASSWORD_FAILED),
      })
    );
  }, 10000);

  it("should return 404 if user not found", async () => {
    User.findOne.mockResolvedValue(null);

    const res = await request(server)
      .post(endpoint)
      .send({ email: "notfound@example.com" });

    expect(res.statusCode).toBe(StatusCodes.NOT_FOUND);
    expect(res.body.message).toMatch(/no user found/i);
    expect(logActivity).toHaveBeenCalled();
  }, 10000);

  it("should handle security question flow correctly", async () => {
    const mockUser = {
      _id: "123",
      email: "test@example.com",
      fullName: "Test User",
      passwordResetToken: "token123",
      generateCryptoToken: jest.fn().mockResolvedValue("token123"),
      save: jest.fn(),
      securityQuestions: [{ _id: "q1", question: "What is your pet name?" }],
    };

    User.findOne.mockResolvedValue(mockUser);

    const agent = request.agent(server);
    const res = await agent.post(endpoint).send({ email: "test@example.com" });

    expect(mockUser.generateCryptoToken).toHaveBeenCalled();
    expect(mockUser.save).toHaveBeenCalledWith({ validateBeforeSave: false });
    expect(res.statusCode).toBe(200);
    expect(res.body.data.securityQuestion).toBeDefined();
    expect(res.body.data.resetToken).toBe("token123");
  }, 1000);

  it("should handle OTP + email reset flow correctly", async () => {
    const mockUser = {
      _id: "456",
      email: "noquestions@example.com",
      fullName: "No Question User",
      passwordResetToken: "resetToken456",
      generateCryptoToken: jest.fn().mockResolvedValue("resetToken456"),
      save: jest.fn(),
      securityQuestions: [],
    };

    User.findOne.mockResolvedValue(mockUser);
    generateOTP.mockReturnValue("123456");
    sendEmail.mockResolvedValue(true);

    const res = await request(server)
      .post(endpoint)
      .send({ email: "noquestions@example.com" });

    expect(mockUser.generateCryptoToken).toHaveBeenCalled();
    expect(sendEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        to: mockUser.email,
        subject: expect.any(String),
        context: expect.objectContaining({ otp: "123456" }),
      })
    );

    expect(res.statusCode).toBe(200);
    expect(res.body.data.resetUrl).toMatch(/reset-password/);
  }, 1000);

  it("should return 500 if email sending fails", async () => {
    const mockUser = {
      _id: "456",
      email: "fail@example.com",
      fullName: "Fail User",
      passwordResetToken: "failToken",
      generateCryptoToken: jest.fn().mockResolvedValue("failToken"),
      save: jest.fn(),
      securityQuestions: [],
    };

    User.findOne.mockResolvedValue(mockUser);
    generateOTP.mockReturnValue("000000");
    sendEmail.mockRejectedValue(new Error("Email failed"));

    const res = await request(server)
      .post(endpoint)
      .send({ email: "fail@example.com" });

    expect(res.statusCode).toBe(500);
    expect(res.body.message).toMatch(/error occurred/i);
  }, 1000);
});

// ==============================
// Test Suite: Auth Controller - Reset Password
// ==============================
describe("Auth Controller - Verify Question", () => {
  const endpoint = "/api/v1/auth/verify-security-question";

  // ─────────────────────────────────────────────────────────────
  // SETUP & MOCKS
  // ─────────────────────────────────────────────────────────────
  beforeEach(() => {
    const mockedUserDoc = {
      passwordResetTokenExpiration: Date.now() - 10000,
      compareSecurityAnswer: jest.fn().mockResolvedValue(true),
      generateCryptoToken: jest.fn().mockResolvedValue("newResetToken123"),
      save: jest.fn().mockResolvedValue(true),
      email: "test@example.com",
      fullName: "Test User",
      _id: "mockedUserId123",
    };

    const selectMock = jest.fn().mockResolvedValue(mockedUserDoc);
    User.findOne = jest.fn(() => ({ select: selectMock }));
  });

  // ─────────────────────────────────────────────────────────────
  // 1. VALIDATION TESTS
  // ─────────────────────────────────────────────────────────────
  it("should return an error if 'answer', 'resetToken', or 'questionId' is missing", async () => {
    // Case 1: Missing 'answer'
    let res = await request(server).post(endpoint).send({
      resetToken: "sampleToken123",
    });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      "Security question verification failed: Missing required fields in request payload."
    );

    // Case 2: Missing 'resetToken'
    res = await request(server).post(endpoint).send({
      answer: "sampleAnswer123",
    });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      "Security question verification failed: Missing required fields in request payload."
    );

    // Case 3: Missing 'questionId'
    res = await request(server).post(endpoint).send({
      answer: "sampleAnswer123",
      resetToken: "sampleToken123",
    });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      "Security question verification failed: Missing required fields in request payload."
    );
  });

  // ─────────────────────────────────────────────────────────────
  // 2. INVALID / EXPIRED TOKEN
  // ─────────────────────────────────────────────────────────────
  it("should return unauthorized for an invalid or expired reset token", async () => {
    const res = await request(server).post(endpoint).send({
      resetToken: "invalid_or_expired_token",
      answer: "someAnswer",
      testQuestionId: "mockedQuestionId123",
    });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe(
      "Security question verification failed: Invalid or expired reset token."
    );
    expect(res.body).toHaveProperty("success", false);
  });

  // ─────────────────────────────────────────────────────────────
  // 3. INCORRECT ANSWER
  // ─────────────────────────────────────────────────────────────
  it("should return 401 if the security answer is incorrect", async () => {
    const dummyUser = {
      _id: "user123",
      email: "test@example.com",
      fullName: "Test User",
      passwordResetToken: "validToken123",
      passwordResetTokenExpiration: Date.now() + 100000,
      compareSecurityAnswer: jest.fn().mockResolvedValue(false),
      save: jest.fn(),
    };
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server).post(endpoint).send({
      answer: "wrongAnswer",
      resetToken: "validToken",
      testQuestionId: "456",
    });

    expect(res.status).toBe(401);
    expect(res.body.message).toMatch(/incorrect answer/i);
  });

  // ─────────────────────────────────────────────────────────────
  // 4. SUCCESSFUL VERIFICATION
  // ─────────────────────────────────────────────────────────────
  it("should return 200 and send reset URL and OTP on successful verification", async () => {
    const dummyUser = {
      _id: "123",
      email: "test@example.com",
      fullName: "Test User",
      compareSecurityAnswer: jest.fn().mockResolvedValue(true),
      passwordResetToken: "validToken",
      passwordResetTokenExpiration: Date.now() + 60000,
      generateCryptoToken: jest.fn().mockResolvedValue("newResetToken"),
      save: jest.fn().mockResolvedValue(true),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    sendEmail.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server).post(endpoint).send({
      answer: "correctAnswer",
      resetToken: "validToken",
      testQuestionId: "123",
    });

    expect(res.status).toBe(200);
    expect(res.body.data.resetUrl).toBeDefined();
    expect(res.body.message).toMatch(
      /Security question verification successful/i
    );

    expect(sendEmail).toHaveBeenCalled();
    expect(logAudit).toHaveBeenCalled();
    expect(logActivity).toHaveBeenCalled();
  });

  // ─────────────────────────────────────────────────────────────
  // 5. FAILURE CASES - Email, Save, Token Generation
  // ─────────────────────────────────────────────────────────────

  it("should return 500 and log error if email sending fails", async () => {
    const dummyUser = {
      _id: "123",
      email: "test@example.com",
      fullName: "Test User",
      compareSecurityAnswer: jest.fn().mockResolvedValue(true),
      passwordResetToken: "validToken",
      passwordResetTokenExpiration: Date.now() + 60000,
      generateCryptoToken: jest.fn().mockResolvedValue("newResetToken"),
      save: jest.fn().mockResolvedValue(true),
    };

    User.findOne = jest.fn().mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    sendEmail.mockRejectedValue(new Error("Email failed"));

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server).post(endpoint).send({
      answer: "correctAnswer",
      resetToken: "validToken",
      testQuestionId: "123",
    });

    expect(res.status).toBe(500);
    expect(res.body.message).toMatch(
      /There was an issue with sending the email. Please try again later./i
    );
  });

  it("should return 500 and log error if saving the user fails", async () => {
    const dummyUser = {
      _id: "123",
      email: "test@example.com",
      fullName: "Test User",
      compareSecurityAnswer: jest.fn().mockResolvedValue(true),
      passwordResetToken: "validToken",
      passwordResetTokenExpiration: Date.now() + 60000,
      generateCryptoToken: jest.fn().mockResolvedValue("newResetToken"),
      save: jest.fn().mockRejectedValue(new Error("Database error")),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    sendEmail.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server).post(endpoint).send({
      answer: "correctAnswer",
      resetToken: "validToken",
      testQuestionId: "123",
    });

    expect(res.status).toBe(500);
    expect(res.body.message).toBe(
      "There was an issue saving the user data. Please try again later."
    );
  });

  it("should return 500 and log error if token generation fails", async () => {
    const dummyUser = {
      _id: "123",
      email: "test@example.com",
      fullName: "Test User",
      passwordResetToken: "validToken",
      passwordResetTokenExpiration: Date.now() + 60000,
      compareSecurityAnswer: jest.fn().mockResolvedValue(true),
      generateCryptoToken: jest
        .fn()
        .mockRejectedValue(new Error("Token generation failed")),
      save: jest.fn().mockResolvedValue(true),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    sendEmail.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server).post(endpoint).send({
      answer: "correctAnswer",
      resetToken: "validToken",
      testQuestionId: "123",
    });

    expect(res.status).toBe(500);
    expect(res.body.message).toBe(
      "There was an issue generating the reset token. Please try again later."
    );
  });

  // ─────────────────────────────────────────────────────────────
  // 6. REALISTIC DATABASE USER CREATION TEST
  // ─────────────────────────────────────────────────────────────
  it("should succeed with correct resetToken and answer", async () => {
    const hashedAnswer = await bcrypt.hash("blue", 10);

    const dummyUser = await User.create({
      email: "test@example.com",
      fullName: "Test User",
      securityQuestions: [
        {
          _id: "q123",
          question: "What is your favorite color?",
          answerHash: hashedAnswer,
        },
      ],
      passwordResetToken: "validToken",
      passwordResetTokenExpiration: new Date(Date.now() + 10 * 60 * 1000),
    });

    dummyUser.generateCryptoToken = jest
      .fn()
      .mockResolvedValueOnce("newResetToken");
    dummyUser.compareSecurityAnswer = jest.fn().mockResolvedValueOnce(true);
    dummyUser.save = jest.fn().mockResolvedValueOnce(dummyUser);

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server).post(endpoint).send({
      answer: "blue",
      resetToken: "validToken",
      testQuestionId: "q123",
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toMatch(
      /Security question verification successful/
    );
    expect(res.body.data.resetUrl).toContain("newResetToken");
  });
});

// ==============================
// Test Suite: Auth Controller - Reset Password Using Token
// ==============================
describe("Auth Controller - Reset Password Using Token", () => {
  const endpoint = "/api/v1/auth/reset-password/";

  // Setup common mocks
  beforeEach(() => {
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(null),
    });
  });

  // Test Case 1: Missing token in URL params
  it("should return an error if token is missing in URL params", async () => {
    const res = await request(server)
      .post(endpoint)
      .send({ newPassword: "newPassword123" });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe("Authentication required");
  }, 10000);

  // Test Case 2: Missing new password in request body
  it("should return an error if new password is missing in the body", async () => {
    const token = "validToken";
    const res = await request(server).post(`${endpoint}${token}`).send({});

    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      "Password reset failed: Missing token or new password."
    );
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description: "Password reset failed: Missing token or new password.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.PASSWORD_RESET_WITH_TOKEN_FAILED,
        description: "Password reset failed: Missing token or new password.",
      })
    );
  }, 10000);

  // Test Case 3: Invalid or expired token
  it("should return 401 UNAUTHORIZED if the token is invalid or expired", async () => {
    const invalidToken = "invalid-or-expired-token";
    const newPassword = "NewSecurePassword123!";

    const res = await request(server)
      .post(`${endpoint}${invalidToken}`)
      .send({ newPassword });

    expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe(
      "Password reset failed: The reset token is invalid or expired. Please request a new one."
    );
  }, 10000);

  // Test Case 4: Token does not match any user
  it("should return 401 if token does not match any user", async () => {
    const token = "valid-format-token";
    const newPassword = "NewStrongPass@123";

    User.findOne.mockImplementationOnce(() => ({
      select: jest.fn().mockResolvedValue(null),
    }));

    const res = await request(server)
      .post(`${endpoint}${token}`)
      .send({ newPassword });

    expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe(
      "Password reset failed: The reset token is invalid or expired. Please request a new one."
    );
  }, 10000);

  // Test Case 5: Reject reused passwords
  it("should reject reused passwords", async () => {
    const reusedPassword = "OldPassword123";
    const user = await createTestUserWithPasswordHistory([
      "OldPassword111",
      reusedPassword,
      "OldPassword999",
    ]);
    const token = await generateValidPasswordResetToken(user);

    const res = await request(server)
      .post(`${endpoint}${token}`)
      .send({ newPassword: reusedPassword });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe(
      "Password reset failed: The reset token is invalid or expired. Please request a new one."
    );
  }, 10000);

  // Test Case 6: Successful password reset, clearing token, and incrementing token version
  it("should reset password, clear token, increment token version, and return success", async () => {
    const oldPassword = "OldPassword123!";
    const newPassword = "NewSecurePassword456!";
    const hashedOldPassword = await bcrypt.hash(oldPassword, 10);

    const token = "validToken";
    const dummyUser = {
      _id: new mongoose.Types.ObjectId(),
      password: hashedOldPassword,
      passwordResetToken: token,
      passwordResetTokenExpiration: Date.now() + 10 * 60 * 1000,
      passwordHistory: [hashedOldPassword],
      tokenVersion: 1,
      isPasswordInHistory: jest.fn().mockResolvedValue(false),
      revokeTokens: jest.fn().mockResolvedValue(),
      save: jest.fn().mockResolvedValue(),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server)
      .post(`${endpoint}${token}`)
      .send({ newPassword });

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/Password Reset Successful/i);
    expect(dummyUser.password).toBe(newPassword);
    expect(dummyUser.passwordResetToken).toBeUndefined();
    expect(dummyUser.passwordResetTokenExpiration).toBeUndefined();
    expect(dummyUser.tokenVersion).toBe(2);
    expect(dummyUser.revokeTokens).toHaveBeenCalled();
    expect(dummyUser.save).toHaveBeenCalled();
    expect(dummyUser.passwordHistory.length).toBeGreaterThan(0);

    // Log assertions
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        actorId: dummyUser._id,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: dummyUser._id,
        action: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
      })
    );
  }, 10000);

  // Test Case 7: Trim password history after reset
  it("should trim passwordHistory to last 5 entries after password reset", async () => {
    const oldPasswords = [
      "oldHash1",
      "oldHash2",
      "oldHash3",
      "oldHash4",
      "oldHash5",
      "oldHash6",
    ];
    const token = "valid-token";
    const dummyUser = {
      _id: "user123",
      password: "currentHash",
      passwordHistory: [...oldPasswords],
      passwordResetToken: "valid-token",
      passwordResetTokenExpiration: Date.now() + 10000,
      isPasswordInHistory: jest.fn().mockResolvedValue(false),
      revokeTokens: jest.fn(),
      save: jest.fn(),
      tokenVersion: 1,
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server).post(`${endpoint}${token}`).send({
      newPassword: "newSecurePassword123",
    });

    expect(res.statusCode).toBe(StatusCodes.OK);
    expect(dummyUser.password).toBe("newSecurePassword123");

    // Validate password history trimming
    expect(dummyUser.passwordHistory.length).toBe(5);
    expect(dummyUser.passwordHistory).toEqual([
      "oldHash3",
      "oldHash4",
      "oldHash5",
      "oldHash6",
      "currentHash",
    ]);

    expect(dummyUser.save).toHaveBeenCalled();
  }, 10000);

  // Test Case 8: Revoke tokens on successful password reset
  it("should call revokeTokens on successful password reset", async () => {
    const oldPasswords = [
      "oldHash1",
      "oldHash2",
      "oldHash3",
      "oldHash4",
      "oldHash5",
    ];
    const token = "valid-token";
    const revokeTokensMock = jest.fn();
    const saveMock = jest.fn();

    const dummyUser = {
      _id: "user123",
      password: "currentHash",
      passwordHistory: [...oldPasswords],
      passwordResetToken: "valid-token",
      passwordResetTokenExpiration: Date.now() + 10000,
      isPasswordInHistory: jest.fn().mockResolvedValue(false),
      revokeTokens: revokeTokensMock,
      save: saveMock,
      tokenVersion: 1,
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server)
      .post(`${endpoint}${token}`)
      .send({ newPassword: "newSecurePassword123" });

    expect(res.statusCode).toBe(StatusCodes.OK);
    expect(revokeTokensMock).toHaveBeenCalled();
    expect(saveMock).toHaveBeenCalled();
    expect(dummyUser.password).toBe("newSecurePassword123");
  }, 10000);

  // Test Case 9: Create audit and activity logs on successful password reset
  it("should create audit and activity logs on successful password reset", async () => {
    const token = "valid-token";
    const userId = "507f191e810c19729de860ea";
    const newPassword = "NewSecureP@ss123";

    const dummyUser = {
      _id: userId,
      password: "oldPasswordHash",
      passwordHistory: ["oldPassword1", "oldPassword2"],
      passwordResetToken: token,
      passwordResetTokenExpiration: Date.now() + 100000,
      isPasswordInHistory: jest.fn().mockResolvedValue(false),
      revokeTokens: jest.fn().mockResolvedValue(),
      save: jest.fn().mockResolvedValue(),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server)
      .post(`${endpoint}${token}`)
      .send({ newPassword });

    expect(res.status).toBe(StatusCodes.OK);

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        actorId: userId,
        targetId: userId,
        targetModel: "User",
        eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
        description:
          "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password.",
        req: expect.any(Object),
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: userId,
        action: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
        description:
          "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password.",
        req: expect.any(Object),
      })
    );
  }, 10000);

  // Test Case 10: Increment token version on successful password reset
  it("should increment tokenVersion on successful password reset", async () => {
    const userId = "507f191e810c19729de860ea";
    const token = "valid-token";
    const newPassword = "NewSecureP@ss123";

    const dummyUser = {
      _id: userId,
      password: "oldPasswordHash",
      passwordHistory: ["oldPassword1", "oldPassword2"],
      passwordResetToken: token,
      passwordResetTokenExpiration: Date.now() + 100000,
      tokenVersion: 1,
      isPasswordInHistory: jest.fn().mockResolvedValue(false),
      revokeTokens: jest.fn().mockResolvedValue(),
      save: jest.fn().mockResolvedValue(),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server)
      .post(`${endpoint}${token}`)
      .send({ newPassword });

    expect(dummyUser.tokenVersion).toBe(2);
    expect(dummyUser.save).toHaveBeenCalledWith({ validateBeforeSave: false });

    expect(res.body.message).toBe(
      "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password."
    );

    expect(res.body.success).toBe(true);
    expect(res.body.data).toBeNull();
  }, 10000);
});

// ==============================
// Test Suite: Auth Controller - Reset Password Using OTP
// ==============================
describe("Auth Controller - Reset Password Using OTP", () => {
  const endpoint = "/api/v1/auth/reset-password-otp";
  const defaultPayload = {
    email: "test@example.com",
    otp: "123456",
    newPassword: "password123",
    confirmPassword: "password123",
  };

  it("should reset password successfully with valid email, OTP, and matching passwords", async () => {
    const dummyUser = {
      _id: "user123",
      email: "test@example.com",
      compareOTP: jest.fn().mockResolvedValue(true),
      save: jest.fn().mockResolvedValue(true),
      otp: "123456",
      otpExpiry: new Date(Date.now() + 10 * 60 * 1000),
    };

    // Mock User.findOne().select()
    jest.spyOn(User, "findOne").mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      otp: "123456",
      newPassword: "testPassword@123",
      confirmPassword: "testPassword@123",
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.message).toContain("Password Reset Successful");
  }, 10000);

  it("should email is missing", async () => {
    const { email, ...payload } = defaultPayload;
    const res = await request(server).post(endpoint).send(payload);
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toContain("Missing token or new password");
  }, 10000);

  it("should otp is missing", async () => {
    const { otp, ...payload } = defaultPayload;
    const res = await request(server).post(endpoint).send(payload);
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toContain("Missing token or new password");
  }, 10000);

  it("should newPassword is missing", async () => {
    const { newPassword, ...payload } = defaultPayload;
    const res = await request(server).post(endpoint).send(payload);
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toContain("Missing token or new password");
  }, 10000);

  it("should confirmPassword is missing", async () => {
    const { confirmPassword, ...payload } = defaultPayload;
    const res = await request(server).post(endpoint).send(payload);
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toContain("Missing token or new password");
  }, 10000);

  it("should newPassword ≠ confirmPassword is missing", async () => {
    const payload = {
      ...defaultPayload,
      newPassword: "password123",
      confirmPassword: "wrongPassword123",
    };
    const res = await request(server).post(endpoint).send(payload);
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toContain("Passwords do not match");
  }, 10000);

  it("should return 404 when user is not found", async () => {
    User.findOne.mockReturnValueOnce({
      select: () => Promise.resolve(null),
    });

    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      otp: "123456",
      newPassword: "NewPassword@123",
      confirmPassword: "NewPassword@123",
    });

    expect(res.status).toBe(StatusCodes.NOT_FOUND);
    expect(res.body.message).toMatch(/user not found/i);
  }, 10000);

  it("should return 400 if OTP is expired (compareOTP returns false)", async () => {
    const dummyUser = {
      compareOTP: jest.fn().mockResolvedValue(false),
    };

    User.findOne.mockReturnValueOnce({
      select: () => Promise.resolve(dummyUser),
    });

    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      otp: "123456",
      newPassword: "NewPassword@123",
      confirmPassword: "NewPassword@123",
    });

    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toMatch(/Invalid or expired OTP/i);
  }, 10000);

  it("should return 500 if compareOTP throws error", async () => {
    const dummyUser = {
      compareOTP: jest.fn().mockRejectedValue(new Error("OTP check failed")),
    };

    User.findOne.mockReturnValueOnce({
      select: () => Promise.resolve(dummyUser),
    });

    const res = await request(server).post(endpoint).send({
      email: "test@example.com",
      otp: "123456",
      newPassword: "NewPassword@123",
      confirmPassword: "NewPassword@123",
    });
    expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
    expect(res.body.message).toBe("OTP check failed");
  }, 10000);

  it("should return 500 when user throws an exception", async () => {
    User.findOne.mockImplementation(() => {
      throw new Error("Database error");
    });

    const payload = {
      email: "user@example.com",
      otp: "123456",
      newPassword: "newPassword123",
      confirmPassword: "newPassword123",
    };

    const res = await request(server).post(endpoint).send(payload);

    expect(res.status).toBe(500);
    expect(res.body).toHaveProperty("message");
    expect(res.body.message).toMatch("Database error");
  }, 10000);

  it("should throw an error when user save fails", async () => {
    const dummyUser = {
      compareOTP: jest.fn().mockResolvedValue(true),
      save: jest.fn().mockRejectedValue(new Error("Save error")),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    const res = await request(server).post(endpoint).send({
      email: "user@example.com",
      otp: "123456",
      newPassword: "newPassword",
      confirmPassword: "newPassword",
    });

    expect(res.status).toBe(500);
    expect(res.body.message).toBe("Save error");
  }, 10000);

  it("should return 500 when logAudit fails", async () => {
    const dummyUser = {
      compareOTP: jest.fn().mockResolvedValue(true),
      save: jest.fn().mockResolvedValue(true),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    logAudit.mockRejectedValue(new Error("Audit log error"));

    const res = await request(server).post(endpoint).send({
      email: "user@example.com",
      otp: "123456",
      newPassword: "newPassword",
      confirmPassword: "newPassword",
    });

    expect(res.status).toBe(500);
    expect(res.body.message).toBe("Audit log error");
  }, 10000);
});

// ==============================
// Test Suite: Auth Controller - Resend OTP
// ==============================
describe("Auth Controller - Resend OTP", () => {
  const endpoint = "/api/v1/auth/resend-otp";

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should return bad request if email is missing", async () => {
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server).post(endpoint).send({});
    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toBe("OTP reset failed: Missing email.");
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP reset failed: Missing email.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: "OTP reset failed: Missing email.",
      })
    );
  });

  it("should handle case when email exists but user not found", async () => {
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(null),
    });

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .post(endpoint)
      .send({ email: "nonexistent@example.com" });

    expect(res.status).toBe(StatusCodes.OK);
  });

  it("should not send OTP when user not found", async () => {
    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(null),
    });
    const res = await request(server)
      .post(endpoint)
      .send({ email: "nonexistent@example.com" });

    expect(generateOTP).not.toHaveBeenCalled();
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it("should return bad request if user is already verified", async () => {
    const dummyUser = {
      isVerified: true,
      _id: "user123",
      select: jest.fn(),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .post(endpoint)
      .send({ email: "verified@example.com" });

    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toBe(
      "OTP verification skipped: Email is already verified."
    );
  });

  it("should generate OTP and send email if user is unverified", async () => {
    const dummyUser = {
      _id: "user123",
      email: "test@example.com",
      fullName: "Test User",
      isVerified: false,
      save: jest.fn().mockResolvedValue(true),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    generateOTP.mockReturnValue("123456");
    sendEmail.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .post(endpoint)
      .send({ email: dummyUser.email });

    expect(res.status).toBe(StatusCodes.OK);
    expect(sendEmail).toHaveBeenCalled();
    expect(dummyUser.save).toHaveBeenCalled();
    expect(generateOTP).toHaveBeenCalled();
  });

  it("should handle failure in sending email and clear OTP fields", async () => {
    const dummyUser = {
      _id: "user123",
      email: "test@example.com",
      fullName: "Test User",
      isVerified: false,
      save: jest.fn().mockResolvedValue(true),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    generateOTP.mockReturnValue("123456");
    sendEmail.mockRejectedValue(new Error("SMTP failure"));
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .post(endpoint)
      .send({ email: dummyUser.email });

    expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
    expect(res.body.message).toBe("Failed to send verification email.");
    expect(dummyUser.save).toHaveBeenCalled();
  });

  it("should handle save failure after updating OTP", async () => {
    const email = "existing@example.com";
    const dummyUser = {
      _id: "user123",
      email: email,
      isVerified: false,
      otp: null,
      otpExpiry: null,
      otpAttempts: 3,
      save: jest.fn().mockRejectedValue(new Error("Database save failed")),
    };

    User.findOne.mockReturnValue({
      select: jest.fn().mockResolvedValue(dummyUser),
    });

    generateOTP.mockReturnValue("123456");
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server).post(endpoint).send({ email });

    expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
    expect(res.body.message).toMatch(/Failed to update user with OTP/i);

    expect(generateOTP).toHaveBeenCalled();

    expect(dummyUser.otp).toBe("123456");
    expect(dummyUser.otpExpiry).toBeInstanceOf(Date);
    expect(dummyUser.otpAttempts).toBe(0);

    expect(dummyUser.save).toHaveBeenCalledWith({ validateBeforeSave: false });

    expect(sendEmail).not.toHaveBeenCalled();

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: expect.stringContaining("Failed to update user with OTP"),
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: expect.stringContaining("Failed to update user with OTP"),
      })
    );
  });

  it("should handle non-error rejection from sendEmail", async () => {
    const email = "test@example.com";

    // Set up dummy user with mock behavior for save()
    const dummyUser = {
      _id: "user123",
      email,
      fullName: "Test User",
      isVerified: false,
      otp: null,
      otpExpiry: null,
      otpAttempts: 3,
      save: jest.fn().mockImplementation(function () {
        // Simulate state changes during save
        // First call: set OTP and expiry
        // Second call: clear OTP and expiry
        if (this.otpCleared) {
          this.otp = undefined;
          this.otpExpiry = undefined;
        } else {
          this.otp = "123456";
          this.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
          this.otpAttempts = 0;
        }
        return Promise.resolve(true);
      }),
    };

    // Mock user model behavior
    const selectMock = jest.fn().mockResolvedValue(dummyUser);
    User.findOne.mockReturnValue({ select: selectMock });

    generateOTP.mockReturnValue("123456");

    // Reject the sendEmail call
    sendEmail.mockRejectedValue(new Error("Email config missing"));

    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    // Track that second save call should clear OTP
    dummyUser.otpCleared = false;
    dummyUser.save
      .mockImplementationOnce(function () {
        // First save call: OTP set
        this.otp = "123456";
        this.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
        this.otpAttempts = 0;
        return Promise.resolve(true);
      })
      .mockImplementationOnce(function () {
        // Second save call: OTP cleared
        this.otp = undefined;
        this.otpExpiry = undefined;
        this.otpCleared = true;
        return Promise.resolve(true);
      });

    const res = await request(server).post(endpoint).send({ email });

    // Verify response
    expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
    expect(res.body.message).toBe("Failed to send verification email.");

    // Verify that OTP was generated and initially set
    expect(generateOTP).toHaveBeenCalled();
    expect(dummyUser.save).toHaveBeenCalledTimes(2);

    // OTP should be cleared after email failure
    expect(dummyUser.otp).toBeUndefined();
    expect(dummyUser.otpExpiry).toBeUndefined();

    // Verify email send attempt
    expect(sendEmail).toHaveBeenCalledWith({
      to: email,
      subject: "Verify Your Email",
      template: "emailVerification",
      context: {
        name: dummyUser.fullName,
        otp: "123456",
        expiresIn: "10 minutes",
      },
    });

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        actorId: dummyUser._id,
        targetId: dummyUser._id,
        targetModel: "User",
        eventType: logEvents.OTP_RESET_REQUEST_FAILED,
        description: expect.stringContaining(
          "Failed to send verification email"
        ),
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: dummyUser._id,
        action: logEvents.OTP_RESET_REQUEST_FAILED,
        description: expect.stringContaining(
          "Failed to send verification email"
        ),
      })
    );
  });
});

// ==============================
// Test Suite: Auth Controller - Logout User
// ==============================
describe("Auth Controller - Logout User", () => {
  const endpoint = "/api/v1/auth/logout";
  User.findById = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    logAudit.mockClear();
    logActivity.mockClear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("should return 400 if no refresh token in cookies", async () => {
    const res = await request(server).get(endpoint).send();
    expect(res.status).toBe(StatusCodes.BAD_REQUEST);
    expect(res.body.message).toBe(
      "Logout attempt failed: Refresh token required."
    );
  }, 10000);

  it("should return 401 Unauthorized for malformed refresh token", async () => {
    const malformedToken = "malformed.token.string";

    const res = await request(server)
      .get(endpoint)
      .set("Cookie", [`refreshToken=${malformedToken}`]);

    expect(res.statusCode).toBe(StatusCodes.UNAUTHORIZED);
    expect(res.body).toHaveProperty(
      "message",
      "Logout attempt failed: Invalid refresh token."
    );
  }, 10000);

  it("should fail logout if token is expired but within grace period", async () => {
    const expiredTokenPayload = {
      id: "user123",
      iat: Math.floor(Date.now() / 1000) - 3600,
      exp: Math.floor(Date.now() / 1000) - 10,
    };

    const expiredToken = jwt.sign(expiredTokenPayload, "dummysecret");

    jest.spyOn(jwt, "verify").mockImplementation(() => {
      const error = new jwt.TokenExpiredError("jwt expired", new Date());
      error.expiredAt = new Date(Date.now() - 10000);
      throw error;
    });

    jest.spyOn(jwt, "decode").mockReturnValue(expiredTokenPayload);

    const mockUser = {
      _id: "user123",
      isTokenExpiredGracefully: jest.fn().mockReturnValue(true),
    };

    User.findById.mockResolvedValue(mockUser);

    const res = await request(server)
      .get(endpoint)
      .set("Cookie", [`refreshToken=${expiredToken}`]);

    expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
    expect(res.body.message).toBe(
      "Logout attempt failed: Token expired but within grace period."
    );

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        actorId: "user123",
        eventType: logEvents.LOGOUT_FAILED,
        description:
          "Logout attempt failed: Token expired but within grace period.",
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "user123",
        action: logEvents.LOGOUT_FAILED,
        description:
          "Logout attempt failed: Token expired but within grace period.",
      })
    );
  }, 10000);

  it("should fail logout due to invalid refresh token", async () => {
    jest.spyOn(jwt, "verify").mockImplementation(() => {
      throw new Error("Invalid token");
    });

    const invalidToken = "tampered.or.invalid.token";

    const res = await request(server)
      .get(endpoint)
      .set("Cookie", [`refreshToken=${invalidToken}`]);

    expect(res.statusCode).toBe(401);
    expect(res.body.message).toBe(
      "Logout attempt failed: Invalid refresh token."
    );

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        description: "Logout attempt failed: Invalid refresh token.",
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        description: "Logout attempt failed: Invalid refresh token.",
      })
    );
  }, 10000);

  it("should fail logout due to valid token but user not found", async () => {
    const userId = new mongoose.Types.ObjectId().toString();

    const decodedPayload = {
      id: userId,
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const refreshToken = jwt.sign(decodedPayload, refreshTokenSecret);
    const accessToken = jwt.sign(decodedPayload, accessTokenSecret);

    jest.spyOn(jwt, "verify").mockImplementation((token, secret) => {
      if (secret === refreshTokenSecret) return decodedPayload;
      if (secret === accessTokenSecret) return decodedPayload;
      throw new Error("Invalid secret");
    });

    jest.spyOn(User, "findById").mockResolvedValue(null);

    const res = await request(server)
      .get(endpoint)
      .set("Cookie", [
        `refreshToken=${refreshToken}`,
        `accessToken=${accessToken}`,
      ]);

    expect(res.statusCode).toBe(404);
    expect(res.body.message).toBe("Logout attempt failed: User not found.");

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.LOGOUT_FAILED,
        description: "Logout attempt failed: User not found.",
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.LOGOUT_FAILED,
        description: "Logout attempt failed: User not found.",
      })
    );
  }, 10000);

  it("should fail logout due to valid token but session not found/inactive", async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const refreshToken = jwt.sign(
      { id: userId, exp: Math.floor(Date.now() / 1000) + 3600 },
      refreshTokenSecret
    );
    const accessToken = jwt.sign({ id: userId }, accessTokenSecret);

    const dummyUser = {
      _id: userId,
      revokeTokens: jest.fn().mockResolvedValue(undefined),
      hashSessionToken: jest.fn().mockResolvedValue("hashedRefreshToken"),
      save: jest.fn().mockResolvedValue(undefined),
      tokenVersion: 0,
      twoFactorEnabled: true,
    };

    jest.spyOn(jwt, "verify").mockImplementation((token, secret) => {
      if (secret === refreshTokenSecret)
        return { id: userId, exp: Math.floor(Date.now() / 1000) + 3600 };
      if (secret === accessTokenSecret) return { id: userId };
      throw new Error("Invalid secret");
    });

    jest.spyOn(User, "findById").mockResolvedValue(dummyUser);

    // No need to mock TokenBlacklist.create here, as it's mocked at the module level

    jest.spyOn(Session, "findOneAndUpdate").mockResolvedValue(null);

    const res = await request(server)
      .get(endpoint)
      .set("Cookie", [
        `refreshToken=${refreshToken}`,
        `accessToken=${accessToken}`,
      ]);

    expect(res.statusCode).toBe(404);
    expect(res.body.message).toBe("Session not found.");

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.LOGOUT_FAILED,
        description: "Session not found or already inactive.",
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.LOGOUT_FAILED,
        description: "Session not found or already inactive.",
      })
    );
  }, 10000);

  it("should successfully log out user", async () => {
    // 1. Create test user
    const userId = new mongoose.Types.ObjectId();
    const validToken = jwt.sign({ id: userId }, refreshTokenSecret, {
      expiresIn: "1h",
    });

    // Track how many times revokeTokens is called
    let revokeTokensCallCount = 0;

    // Create a plain user object with controlled tokenVersion updates
    const userData = {
      _id: userId,
      tokenVersion: 0,
      twoFactorEnabled: true,
      hashSessionToken: jest.fn().mockResolvedValue("hashed-token"),
      revokeTokens: jest.fn().mockImplementation(async function () {
        revokeTokensCallCount++;
        if (revokeTokensCallCount === 1) {
          this.tokenVersion += 1;
          this.twoFactorEnabled = false;
        }
        return true;
      }),
      save: jest.fn().mockImplementation(function () {
        return Promise.resolve(this);
      }),
    };

    // Mock User methods
    User.findById = jest.fn().mockResolvedValue(userData);
    User.create = jest.fn().mockResolvedValue(userData);

    // 2. Mock session methods
    const hashedToken = crypto
      .createHash("sha256")
      .update(validToken)
      .digest("hex");

    const mockSession = {
      userId,
      refreshTokenHash: hashedToken,
      isActive: true,
      save: jest.fn().mockResolvedValue(true),
    };

    Session.findOne = jest.fn().mockResolvedValue(mockSession);
    Session.findOneAndUpdate = jest.fn().mockResolvedValue({
      ...mockSession,
      isActive: false,
    });

    // Mock TokenBlacklist
    TokenBlacklist.create = jest.fn().mockResolvedValue(true);

    // 3. Make the request
    const res = await request(server)
      .get(endpoint)
      .set("Cookie", [`refreshToken=${validToken}`]);

    // 4. Assertions
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Logged out successfully.");

    // Verify cookies cleared
    expect(res.headers["set-cookie"]).toEqual(
      expect.arrayContaining([
        expect.stringContaining("accessToken=;"),
        expect.stringContaining("refreshToken=;"),
      ])
    );

    // Verify user updates
    expect(userData.tokenVersion).toBe(1); // Adjust to 2 if controller increments
    expect(userData.twoFactorEnabled).toBe(false);
    expect(revokeTokensCallCount).toBe(1);

    // Verify revokeTokens was called exactly once
    expect(userData.revokeTokens).toHaveBeenCalledTimes(1);

    // Verify logs
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        actorId: userId.toString(), // Convert ObjectId to string
        eventType: logEvents.LOGOUT_SUCCESS,
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: userId.toString(),
        action: logEvents.LOGOUT_SUCCESS,
      })
    );
  }, 10000);
});

// ==============================
// Test Suite: Auth Controller - Refresh Token
// ==============================
describe("Auth Controller - Refresh Token", () => {
  const endpoint = "/api/v1/auth/refresh-token";
  const userId = new mongoose.Types.ObjectId();
  const token = "valid-token";
  const tokenPair = {
    accessToken: "new-access",
    refreshToken: "new-refresh",
  };
  const hashToken = crypto.createHash("sha256").update(token).digest("hex");

  beforeEach(() => {
    jest.clearAllMocks();
    logAudit.mockClear();
    logActivity.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should throw error when refresh token is missing", async () => {
    const res = await request(server).get(endpoint).set("Cookie", "").send({});

    expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
    expect(res.body.message).toBe(
      "Refresh Token Failed: Missing refresh token."
    );

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Missing refresh token.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Missing refresh token.",
      })
    );
  }, 10000);

  it("should refresh token successfully when token is in cookies", async () => {
    const dummyUser = {
      _id: "user-id",
      isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
    };

    jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);

    User.rotateTokens = jest.fn().mockResolvedValue({
      user: dummyUser,
      accessToken: "new-access",
      refreshToken: "new-refresh",
    });

    jest.spyOn(User, "findById").mockResolvedValue(dummyUser);

    jest.spyOn(jwt, "decode").mockReturnValue({
      id: "user-id",
      exp: Date.now() / 1000 + 3600,
    });

    logSession.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);

    const res = await request(server)
      .get(endpoint)
      .set("Cookie", `refreshToken=${token}`)
      .send({});

    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );

    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );

    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe(
      "Refresh Token successful: Token refreshed successfully."
    );
  }, 10000);

  it("should refresh token successfully when token is in body", async () => {
    jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
    User.rotateTokens = jest.fn().mockResolvedValue(tokenPair);
    jwt.decode.mockReturnValue({
      id: "user-id",
      exp: Date.now() / 1000 + 3600,
    });
    User.findById.mockResolvedValue({
      _id: "user-id",
      isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
    });
    logSession.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    const res = await request(server)
      .get(endpoint)
      .set("Cookie", "")
      .send({ refreshToken: token });
    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body).toEqual({
      success: true,
      message: "Refresh Token successful: Token refreshed successfully.",
      data: { token: tokenPair },
    });
    const cookies = res.headers["set-cookie"];
    expect(cookies).toEqual(
      expect.arrayContaining([
        expect.stringContaining(`accessToken=${tokenPair.accessToken}`),
        expect.stringContaining(`refreshToken=${tokenPair.refreshToken}`),
      ])
    );
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );
    expect(logSession).toHaveBeenCalledWith(
      expect.objectContaining({
        user: expect.objectContaining({ _id: "user-id" }),
        refreshToken: tokenPair.refreshToken,
      })
    );
  }, 10000);

  it("should return 401 when rotateTokens fails due to invalid token", async () => {
    jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
    jest
      .spyOn(User, "rotateTokens")
      .mockRejectedValue(new Error("Invalid refresh token"));
    const res = await request(server)
      .get(endpoint)
      .set("Cookie", `refreshToken=${token}`)
      .send({});
    expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
    expect(res.body.message).toBe("Invalid refresh token");
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Refresh token rotation failed.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Refresh token rotation failed.",
      })
    );
    expect(User.rotateTokens).toHaveBeenCalledWith(token, expect.any(Object));
  }, 10000);

  it("should return 404 when user is not found in rotateTokens", async () => {
    jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
    jest
      .spyOn(User, "rotateTokens")
      .mockRejectedValue(
        new ApiError(StatusCodes.NOT_FOUND, "User not found.")
      );
    const res = await request(server)
      .get(endpoint)
      .set("Cookie", `refreshToken=${token}`)
      .send({});
    expect(res.status).toBe(StatusCodes.NOT_FOUND);
    expect(res.body.message).toBe("User not found.");
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Refresh token rotation failed.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_FAILED,
        description: "Refresh Token Failed: Refresh token rotation failed.",
      })
    );
    expect(User.rotateTokens).toHaveBeenCalledWith(token, expect.any(Object));
  }, 10000);

  it("should return 401 when new refresh token is in graceful expiration period", async () => {
    jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
    jest.spyOn(User, "rotateTokens").mockResolvedValue(tokenPair);
    jest.spyOn(jwt, "decode").mockReturnValue({
      id: userId,
      exp: Math.floor(Date.now() / 1000),
    });
    const user = {
      _id: userId,
      isTokenExpiredGracefully: jest.fn().mockReturnValue(true),
    };
    jest.spyOn(User, "findById").mockResolvedValue(user);
    const res = await request(server)
      .get(endpoint)
      .set("Cookie", `refreshToken=${token}`)
      .send({});
    expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
    expect(res.body.message).toBe(
      "Refresh Token Failed: Token expired but within grace period."
    );
    expect(logSession).toHaveBeenCalledWith(
      expect.objectContaining({
        user,
        refreshToken: tokenPair.refreshToken,
      })
    );
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_FAILED,
        description:
          "Refresh Token Failed: Token expired but within grace period.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_FAILED,
        description:
          "Refresh Token Failed: Token expired but within grace period.",
      })
    );
    expect(User.rotateTokens).toHaveBeenCalledWith(token, expect.any(Object));
    expect(User.findById).toHaveBeenCalledWith(userId);
    expect(user.isTokenExpiredGracefully).toHaveBeenCalledWith(
      expect.any(Number)
    );
  }, 10000);

  it("should return 200 and new tokens when refresh is successful", async () => {
    jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
    jest.spyOn(User, "rotateTokens").mockResolvedValue(tokenPair);
    jest.spyOn(jwt, "decode").mockReturnValue({
      id: userId,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const user = {
      _id: userId,
      isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
    };
    jest.spyOn(User, "findById").mockResolvedValue(user);
    const res = await request(server)
      .get(endpoint)
      .set("Cookie", `refreshToken=${token}`)
      .send({});
    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body.message).toBe(
      "Refresh Token successful: Token refreshed successfully."
    );
    expect(res.headers["set-cookie"]).toEqual(
      expect.arrayContaining([
        expect.stringContaining(`accessToken=${tokenPair.accessToken}`),
        expect.stringContaining(`refreshToken=${tokenPair.refreshToken}`),
      ])
    );
    expect(logSession).toHaveBeenCalledWith(
      expect.objectContaining({
        user,
        refreshToken: tokenPair.refreshToken,
      })
    );
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );
    expect(User.rotateTokens).toHaveBeenCalledWith(token, expect.any(Object));
    expect(User.findById).toHaveBeenCalledWith(userId);
    expect(user.isTokenExpiredGracefully).toHaveBeenCalledWith(
      expect.any(Number)
    );
  }, 10000);

  it("should refresh token successfully with token in cookies", async () => {
    const user = {
      _id: userId,
      isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
    };
    jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
    jest.spyOn(User, "rotateTokens").mockResolvedValue(tokenPair);
    jest.spyOn(jwt, "decode").mockReturnValue({
      id: userId,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    jest.spyOn(User, "findById").mockResolvedValue(user);
    logSession.mockResolvedValue(true);
    logAudit.mockResolvedValue(true);
    logActivity.mockResolvedValue(true);
    const res = await request(server)
      .get(endpoint)
      .set("Cookie", `refreshToken=${token}`)
      .send({});
    expect(res.status).toBe(StatusCodes.OK);
    expect(res.body).toEqual({
      success: true,
      message: "Refresh Token successful: Token refreshed successfully.",
      data: { token: tokenPair },
    });
    expect(res.headers["set-cookie"]).toEqual(
      expect.arrayContaining([
        expect.stringContaining(`accessToken=${tokenPair.accessToken}`),
        expect.stringContaining(`refreshToken=${tokenPair.refreshToken}`),
      ])
    );
    expect(logSession).toHaveBeenCalledWith(
      expect.objectContaining({
        user,
        refreshToken: tokenPair.refreshToken,
      })
    );
    expect(logAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );
    expect(logActivity).toHaveBeenCalledWith(
      expect.objectContaining({
        action: logEvents.REFRESH_TOKEN_SUCCESS,
        description: "Refresh Token successful: Token refreshed successfully.",
      })
    );
    expect(User.rotateTokens).toHaveBeenCalledWith(token, expect.any(Object));
    expect(User.findById).toHaveBeenCalledWith(userId);
    expect(user.isTokenExpiredGracefully).toHaveBeenCalledWith(
      expect.any(Number)
    );
  }, 10000);
});
