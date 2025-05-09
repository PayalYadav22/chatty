// ==============================
// External Packages
// ==============================
import { jest } from "@jest/globals";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { StatusCodes } from "http-status-codes";

// ==============================
// Mocked Modules
// ==============================
jest.unstable_mockModule("../../models/user.model.js", () => ({
  default: {
    findById: jest.fn(),
    findOne: jest.fn(),
    verifyRecaptcha: jest.fn(),
    rotateTokens: jest.fn(),
    create: jest.fn(),
    findByIdAndDelete: jest.fn(),
  },
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
    findOne: jest.fn(),
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
// Constants
// ==============================
const { logEvents, refreshTokenSecret, accessTokenSecret, sessionExpiry } =
  await import("../../constants/constant.js");

// ==============================
// Config & Services
// ==============================
const { uploadFileToCloudinary, deleteFileToCloudinary } = await import(
  "../../config/cloudinary.config.js"
);
const sendEmail = (await import("../../utils/email.js")).default;
const generateOTP = (await import("../../utils/otp.js")).default;
const { logAudit } = await import("../../utils/logger.js");
const { logActivity } = await import("../../utils/logger.js");
const { logLoginAttempt } = await import("../../utils/logger.js");
const { logSession } = await import("../../utils/logger.js");

// ==============================
// Mock User Objects
// ==============================
const dummyUser = {
  _id: new mongoose.Types.ObjectId(),
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
  isVerified: true,
  isLocked: false,
  lockUntil: null,
  loginAttempts: 0,
  tokenExpirationTime: new Date(Date.now() + 3600 * 1000),
  twoFactorSecret: "secret",
  twoFactorEnabled: false,
  otp: "123456",
  otpExpiry: Date.now() + 15 * 60 * 1000,
  recaptchaToken: "dummy-recaptcha-token",
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
  resetOtpAttempts: jest.fn().mockResolvedValue(false),
  enableTwoFactor: jest
    .fn()
    .mockResolvedValue({ qrCodeDataURL: "fake-qr-code-url" }),
  compareOTP: jest.fn().mockResolvedValue(true),
  comparePassword: jest.fn().mockResolvedValue(true),
  isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
  verifyAndEnableTwoFactor: jest.fn().mockResolvedValue(true),
  incLoginAttempts: jest.fn().mockResolvedValue(undefined),
  resetLoginAttempts: jest.fn().mockResolvedValue(undefined),
  generateCryptoToken: jest.fn().mockResolvedValue(false),
  passwordResetTokenExpiration: Date.now() - 10000,
  compareSecurityAnswer: jest.fn().mockResolvedValue(true),
  save: jest.fn().mockResolvedValue(true),
};

const emptyUser = {
  fullName: "",
  email: "",
  phone: "",
  userName: "",
  password: "",
  recaptchaToken: "",
};

// ==============================
// Mock Token Object
// ==============================
const dummyToken = {
  accessToken: "mockAccessToken",
  refreshToken: "mockRefreshToken",
};

// ==============================
// Mock Constant Token
// ==============================
const refreshToken = jwt.sign(
  { id: dummyUser._id.toString() },
  refreshTokenSecret,
  { expiresIn: "1h" }
);

// ==============================
// Required Fields Arrays
// ==============================
const requiredFields = [
  "fullName",
  "email",
  "phone",
  "userName",
  "password",
  "recaptchaToken",
];

const verifyRequiredFields = ["email", "otp"];

const verifyQuestionRequiredFields = ["answer", "resetToken", "questionId"];

const resetPasswordOtpRequiredFields = [
  "email",
  "otp",
  "newPassword",
  "confirmPassword",
];

// ==============================
// Helper Functions
// ==============================

const hashedSessionToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

const generateValidPasswordResetToken = async (user) => {
  const token = crypto.randomBytes(32).toString("hex");
  user.passwordResetToken = token;
  user.passwordResetTokenExpiration = Date.now() + 3600000;
  await user.save();
  return token;
};

const createTestUserWithPasswordHistory = async (passwordHistory) => {
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
};

// ==============================
// Test Suite: Auth Controller - User Register
// ==============================
describe("Auth Controller - Registration", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/register";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeAll(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Errors", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
    for (const field of requiredFields) {
      it(`should fail if ${field} is missing`, async () => {
        const payload = { ...dummyUser };
        delete payload[field];

        const res = await request(server).post(endpoint).send(payload);

        expect(res.status).toBe(StatusCodes.BAD_REQUEST);
        expect(res.body.message).toContain(`"${field}" is required`);
      });
    }

    it("should fail if required fields are empty", async () => {
      const res = await request(server).post(endpoint).send({
        fullName: "",
        email: "",
        phone: "",
        userName: "",
        password: "",
        recaptchaToken: "",
      });

      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toContain(
        '"fullName" is not allowed to be empty'
      );
      expect(res.body.message).toContain('"email" is not allowed to be empty');
      expect(res.body.message).toContain(
        '"recaptchaToken" is not allowed to be empty'
      );
    });
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should fail if reCAPTCHA token is missing", async () => {
      const payload = { ...dummyUser, recaptchaToken: undefined };
      const res = await request(server).post(endpoint).send(payload);
      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toContain(`"recaptchaToken" is required`);
    });

    it("should fail if avatar image is not uploaded", async () => {
      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("userName", dummyUser.userName)
        .field("phone", dummyUser.phone)
        .field("password", dummyUser.password)
        .field("recaptchaToken", "valid-token-123");

      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toBe(
        "Registration failed: Missing avatar image."
      );
    });

    it("should fail if Cloudinary upload fails", async () => {
      uploadFileToCloudinary.mockResolvedValue(null);
      jest.spyOn(User, "findOne").mockResolvedValue(null);
      jest.spyOn(User, "verifyRecaptcha").mockResolvedValue({ success: true });

      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("userName", dummyUser.userName)
        .field("phone", dummyUser.phone)
        .field("password", dummyUser.password)
        .field("recaptchaToken", "valid-token-123")
        .attach("avatar", "src/tests/fixtures/avatar.jpg");

      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toBe(
        "Registration failed: Avatar upload to Cloudinary failed."
      );
    });

    it("should fail if user with same email or phone exists", async () => {
      jest.spyOn(User, "findOne").mockResolvedValue(dummyUser);

      uploadFileToCloudinary.mockResolvedValueOnce({
        success: true,
        data: {
          secure_url: "https://cloudinary.com/fake-avatar.jpg",
          public_id: "avatar123",
        },
      });

      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("userName", dummyUser.userName)
        .field("phone", dummyUser.phone)
        .field("password", dummyUser.password)
        .field("recaptchaToken", "valid-token-123")
        .attach("avatar", "src/tests/fixtures/avatar.jpg");

      expect(res.status).toBe(StatusCodes.CONFLICT);
      expect(res.body.message).toBe(
        "Registration failed: User with same email or phone already exists."
      );
    });

    it("should fail if avatar upload to Cloudinary fails", async () => {
      jest.spyOn(User, "findOne").mockResolvedValue(null);

      jest.spyOn(User, "create").mockResolvedValue({
        _id: "someUserId",
        email: dummyUser.email,
        fullName: dummyUser.fullName,
        userName: dummyUser.userName,
        phone: dummyUser.phone,
        resetOtpAttempts: jest.fn(),
      });

      uploadFileToCloudinary.mockResolvedValueOnce(false);

      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("userName", dummyUser.userName)
        .field("phone", dummyUser.phone)
        .field("password", dummyUser.password)
        .field("recaptchaToken", "valid-token-123")
        .attach("avatar", "src/tests/fixtures/avatar.jpg");

      expect(res.status).toBe(400);
      expect(res.body.message).toBe(
        "Registration failed: Avatar upload to Cloudinary failed."
      );
    });

    it("should fail if reCAPTCHA verification fails", async () => {
      jest.spyOn(User, "findOne").mockResolvedValue(null);
      jest.spyOn(User, "verifyRecaptcha").mockResolvedValue({ success: false });

      uploadFileToCloudinary.mockResolvedValue({
        secure_url: "avatar_url",
        public_id: "avatar_public_id",
      });

      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("userName", dummyUser.userName)
        .field("phone", dummyUser.phone)
        .field("password", dummyUser.password)
        .field("recaptchaToken", "invalid-token")
        .attach("avatar", "src/tests/fixtures/avatar.jpg");

      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toBe(
        "Registration failed: Invalid reCAPTCHA verification."
      );
    });

    it("should fail and clean up if email sending fails after registration", async () => {
      jest.spyOn(User, "findOne").mockResolvedValue(null);
      jest.spyOn(User, "verifyRecaptcha").mockResolvedValue({ success: true });
      uploadFileToCloudinary.mockResolvedValue({
        secure_url: "avatar_url",
        public_id: "avatar_public_id",
      });

      const mokeUser = {
        ...dummyUser,
        _id: "user123",
        resetOtpAttempts: jest.fn().mockResolvedValue(true),
      };
      jest.spyOn(User, "create").mockResolvedValue(mokeUser);
      sendEmail.mockRejectedValue(new Error("Email failed"));

      jest.spyOn(User, "findByIdAndDelete").mockResolvedValue(true);
      deleteFileToCloudinary.mockResolvedValueOnce(true);
      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("userName", dummyUser.userName)
        .field("phone", dummyUser.phone)
        .field("password", dummyUser.password)
        .field("recaptchaToken", "valid-token-123")
        .attach("avatar", "src/tests/fixtures/avatar.jpg");

      expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
      expect(res.body.message).toBe(
        "Registration failed: An error occurred during the email verification process. Please try again later."
      );
    });

    it("should return 500 if unexpected error occurs", async () => {
      jest.spyOn(User, "findOne").mockImplementation(() => {
        throw new Error("Something went wrong");
      });

      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("phone", dummyUser.phone)
        .field("userName", dummyUser.userName)
        .field("password", dummyUser.password)
        .field("recaptchaToken", dummyUser.recaptchaToken)
        .attach("avatar", "src/tests/fixtures/avatar.jpg");

      expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
      expect(res.body.message).toContain("Something went wrong");
    });
  });

  // =============================================================================
  // Group: Successful Registration
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
    it("should register a new user successfully", async () => {
      sendEmail.mockResolvedValue(true);
      uploadFileToCloudinary.mockResolvedValue({
        secure_url: "avatar_url",
        public_id: "avatar_public_id",
      });

      jest.spyOn(User, "findOne").mockResolvedValue(null);
      jest.spyOn(User, "create").mockResolvedValue({
        ...dummyUser,
        resetOtpAttempts: jest.fn().mockResolvedValue(true),
        save: jest.fn().mockResolvedValue(true),
      });

      jest.spyOn(User, "verifyRecaptcha").mockResolvedValue({ success: true });

      const res = await request(server)
        .post(endpoint)
        .field("fullName", dummyUser.fullName)
        .field("email", dummyUser.email)
        .field("userName", dummyUser.userName)
        .field("phone", dummyUser.phone)
        .field("password", dummyUser.password)
        .field("recaptchaToken", "valid-token-123")
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

      expect(res.status).toBe(StatusCodes.CREATED);
      expect(res.body.message).toBe(
        "Registration successfully: User successfully completed the registration process. Please verify your email."
      );
      expect(res.body.data).toHaveProperty("id");
      expect(User.create).toHaveBeenCalledTimes(1);
      expect(generateOTP).toHaveBeenCalledTimes(1);
      expect(sendEmail).toHaveBeenCalledTimes(1);
      expect(logAudit).toHaveBeenCalledTimes(1);
      expect(logActivity).toHaveBeenCalledTimes(1);

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
});

// ==============================
// Test Suite: Auth Controller - Verify Email
// ==============================
describe("Auth Controller - Verify Email", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/verify-email";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeAll(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Errors", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
    for (const field of verifyRequiredFields) {
      it(`should fail if ${field} is missing`, async () => {
        const payload = { ...dummyUser };
        delete payload[field];

        const res = await request(server).post(endpoint).send(payload);

        expect(res.status).toBe(StatusCodes.BAD_REQUEST);
        expect(res.body.message).toContain(`"${field}" is required`);
      });
    }
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should return 400 for invalid or expired OTP", async () => {
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(null),
      });
      const res = await request(server)
        .post(endpoint)
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
      dummyUser.isVerified = false;
      logSession.mockResolvedValue(true);
      const res = await request(server)
        .post(endpoint)
        .send({ email: "test@example.com", otp: "123456" });
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
        .post(endpoint)
        .send({ email: "user@example.com", otp: "123456" });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe(
        "Email verification failed: User not found."
      );
      expect(logAudit).toHaveBeenCalled();
      expect(logActivity).toHaveBeenCalled();
    }, 10000);

    it("should return 400 if OTP is incorrect", async () => {
      dummyUser.isVerified = false;
      dummyUser.compareOTP = jest.fn().mockResolvedValue(false);
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(dummyUser),
      });
      const res = await request(server)
        .post(endpoint)
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
        .post(endpoint)
        .send({ email: "user@example.com", otp: "123456" });
      expect(res.status).toBe(400);
      expect(res.body.message).toBe(
        "Email verification failed: User is already verified."
      );
      expect(logAudit).toHaveBeenCalled();
      expect(logActivity).toHaveBeenCalled();
    }, 10000);

    it("should return 500 if enabling two-factor authentication fails", async () => {
      dummyUser.isVerified = false;
      dummyUser.compareOTP = jest.fn().mockResolvedValue(true);
      dummyUser.enableTwoFactor = jest.fn().mockRejectedValue();
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(dummyUser),
      });
      const res = await request(server)
        .post(endpoint)
        .send({ email: "test@example.com", otp: "123456" });
      expect(res.status).toBe(500);
      expect(res.body.message).toMatch(
        "Failed to enable Two-Factor Authentication"
      );
      expect(logAudit).toHaveBeenCalled();
      expect(logActivity).toHaveBeenCalled();
    }, 10000);

    it("should return 500 if createSession fails", async () => {
      dummyUser.isVerified = false;
      dummyUser.compareOTP = jest.fn().mockResolvedValue(true);
      dummyUser.enableTwoFactor = jest.fn().mockResolvedValue({
        qrCodeDataURL: "mockQRCode",
      });

      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(dummyUser),
      });

      logSession.mockRejectedValue(new Error("Session error"));

      User.generateToken = jest.fn().mockResolvedValue({
        accessToken: "access-token",
        refreshToken: "refresh-token",
      });

      const res = await request(server)
        .post(endpoint)
        .send({ email: "test@example.com", otp: "123456" });

      expect(res.status).toBe(500);
      expect(res.body.message).toMatch("Session creation failed");
      expect(logAudit).toHaveBeenCalled();
      expect(logActivity).toHaveBeenCalled();
    }, 10000);

    it("should return 500 if compareOTP is not a function", async () => {
      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockResolvedValue({
          email: "test@example.com",
          compareOTP: undefined,
        }),
      });

      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        otp: "123456",
      });

      expect(res.statusCode).toBe(500);
      expect(res.body.message).toBe("user.compareOTP is not a function");
    }, 10000);

    it("should return 500 if token generation fails", async () => {
      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockResolvedValue({
          email: "test@example.com",
          compareOTP: jest.fn().mockResolvedValue(true),
          enableTwoFactor: jest.fn().mockResolvedValue(true),
          save: jest.fn(),
        }),
      });

      jest.spyOn(User, "generateToken").mockImplementation(() => {
        throw new Error("token generation failed");
      });

      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        otp: "123456",
      });

      expect(res.statusCode).toBe(500);
      expect(res.body.message).toBe("token generation failed");
    }, 10000);

    it("should return 500 if save fails", async () => {
      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockReturnValue(
          Promise.resolve({
            email: "test@example.com",
            compareOTP: jest.fn().mockResolvedValue(true),
            enableTwoFactor: jest.fn().mockResolvedValue(true),
            save: jest.fn().mockRejectedValue(new Error("db write failed")),
          })
        ),
      });
      jest.spyOn(User, "generateToken").mockReturnValue("fake-token");
      logSession.mockResolvedValue(true);
      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        otp: "123456",
      });
      expect(res.statusCode).toBe(500);
      expect(res.body.message).toMatch("db write failed");
    }, 10000);
  });

  // =============================================================================
  // Group: Successful Verify Email
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
    it("should verify the user successfully with correct email and OTP", async () => {
      dummyUser.otp = "123456";
      dummyUser.isVerified = false;
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(dummyUser),
      });
      logSession.mockResolvedValue(true);
      const res = await request(server).post(endpoint).send({
        email: dummyUser.email,
        otp: dummyUser.otp,
      });
      expect(res.statusCode).toBe(200);
      expect(res.body.message).toBe(
        "Email verified successfully. Please scan the QR code to complete your 2FA setup and log in."
      );
      expect(dummyUser.save).toHaveBeenCalled();
    });
  });
});

// ==============================
// Test Suite: Auth Controller - Login
// ==============================
describe("Auth Controller - Login", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/login";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeAll(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
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
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
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

    it("should fail if token is expired within grace period", async () => {
      const user = {
        ...dummyUser,
        isTokenExpiredGracefully: jest.fn().mockReturnValue(true),
      };
      User.findOne = jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue(user),
      });
      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        password: "Password123!",
        twoFactorCode: "123456",
      });
      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(res.body.message).toBe(
        "Login attempt failed: Token expired but within grace period, login attempt denied."
      );
      expect(logAudit).toHaveBeenCalledWith({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: "LOGIN_FAILED",
        description:
          "Login attempt failed: Token expired but within grace period, login attempt denied.",
        req: expect.any(Object),
      });
      expect(logActivity).toHaveBeenCalled();
      expect(logLoginAttempt).toHaveBeenCalled();
    }, 10000);

    it("should fail if password is invalid", async () => {
      const user = {
        ...dummyUser,
        comparePassword: jest.fn().mockResolvedValue(false),
      };
      User.findOne = jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue(user),
      });
      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        password: "WrongPassword",
        twoFactorCode: "123456",
      });
      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(res.body.message).toBe(
        "Login attempt failed: Authentication failed."
      );
      expect(user.incLoginAttempts).toHaveBeenCalled();
      expect(logAudit).toHaveBeenCalledWith({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Invalid password.",
        req: expect.any(Object),
      });
      expect(logActivity).toHaveBeenCalled();
      expect(logLoginAttempt).toHaveBeenCalled();
    }, 10000);

    it("should fail if account is locked", async () => {
      const lockUntil = new Date(Date.now() + 120000);
      const user = { ...dummyUser, isLocked: true, lockUntil };
      User.findOne = jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue(user),
      });
      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        password: "Password123!",
        twoFactorCode: "123456",
      });
      expect(res.status).toBe(StatusCodes.FORBIDDEN);
      expect(res.body.message).toBe(
        "Login attempt failed: Account locked. Try again in 2 minutes."
      );
      expect(logAudit).toHaveBeenCalledWith({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: expect.stringContaining("Account locked"),
        req: expect.any(Object),
      });
      expect(logActivity).toHaveBeenCalled();
      expect(logLoginAttempt).toHaveBeenCalled();
    }, 10000);

    it("should fail if email is not verified", async () => {
      const user = { ...dummyUser, isVerified: false };
      User.findOne = jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue(user),
      });
      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        password: "Password123!",
        twoFactorCode: "123456",
      });
      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(res.body.message).toBe(
        "Login attempt failed: Email address not verified."
      );
      expect(logAudit).toHaveBeenCalledWith({
        actorId: user._id,
        targetId: user._id,
        targetModel: "User",
        eventType: logEvents.LOGIN_FAILED,
        description: "Login attempt failed: Email address not verified.",
        req: expect.any(Object),
      });
      expect(logActivity).toHaveBeenCalled();
      expect(logLoginAttempt).toHaveBeenCalled();
    }, 10000);

    it("should fail if 2FA code is missing and 2FA is not enabled", async () => {
      logAudit.mockResolvedValue();
      logActivity.mockResolvedValue();
      logLoginAttempt.mockResolvedValue();

      const res = await request(server).post(endpoint).send({
        email: "test@gmail.com",
        password: "Password123!",
      });

      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toBe(
        'Validation error: "twoFactorCode" is required'
      );

      expect(logAudit).not.toHaveBeenCalled();
      expect(logActivity).not.toHaveBeenCalled();
      expect(logLoginAttempt).not.toHaveBeenCalled();
    }, 10000);
  });

  // =============================================================================
  // Group: Successful Verify Email
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
    it("should login successfully with correct credentials and 2FA", async () => {
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(dummyUser),
      });
      User.generateToken = jest.fn().mockResolvedValue(dummyToken);
      logSession.mockResolvedValue(true);
      logAudit.mockResolvedValue(true);
      logActivity.mockResolvedValue(true);
      logLoginAttempt.mockResolvedValue(true);

      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        password: "StrongPass123!",
        twoFactorCode: "123456",
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.data.email).toBe("test@example.com");
      expect(res.body.message).toMatch(
        `Login Successful: Welcome back, Test User! Login was successful.`
      );

      expect(User.findOne).toHaveBeenCalledWith({
        $or: [{ email: "test@example.com" }, { phone: undefined }],
      });

      expect(dummyUser.comparePassword).toHaveBeenCalledWith("StrongPass123!");
      expect(dummyUser.verifyAndEnableTwoFactor).toHaveBeenCalledWith(
        dummyUser._id,
        "123456"
      );

      expect(User.generateToken).toHaveBeenCalledWith(dummyUser._id);
      expect(logSession).toHaveBeenCalled();
      expect(logAudit).toHaveBeenCalled();
      expect(logActivity).toHaveBeenCalled();
      expect(logLoginAttempt).toHaveBeenCalled();
    });
  });
});

// ==============================
// Test Suite: Auth Controller - Forgot Password
// ==============================
describe("Auth Controller - forgot Password", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/forgot-password";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeAll(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should return 400 if email is missing", async () => {
      const res = await request(server).post(endpoint).send({});
      expect(res.statusCode).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toBe(
        "Password forgot request failed: Missing email address in the request payload."
      );
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: expect.stringContaining(logEvents.FORGOT_PASSWORD_FAILED),
        })
      );
    }, 10000);
  });

  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should return 404 if user not found", async () => {
      User.findOne.mockResolvedValue(null);

      const res = await request(server)
        .post(endpoint)
        .send({ email: "notfound@example.com" });

      expect(res.statusCode).toBe(StatusCodes.NOT_FOUND);
      expect(res.body.message).toBe(
        "Password forgot request failed: No user found for the email address: notfound@example.com."
      );
      expect(logActivity).toHaveBeenCalled();
    }, 10000);

    it("should handle security question flow correctly", async () => {
      User.findOne.mockResolvedValue(dummyUser);

      const res = await request(server)
        .post(endpoint)
        .send({ email: "test@example.com" });

      expect(dummyUser.generateCryptoToken).toHaveBeenCalled();
      expect(dummyUser.save).toHaveBeenCalledWith({
        validateBeforeSave: false,
      });
      expect(res.statusCode).toBe(200);
      expect(res.body.data.securityQuestion).toBeDefined();
      expect(res.body.data.resetToken).toBe(false);
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

    it("should handle user save failure during token generation", async () => {
      const dummyUserWithError = {
        ...dummyUser,
        save: jest.fn().mockRejectedValue(new Error("Save failed")),
      };

      User.findOne.mockResolvedValue(dummyUserWithError);

      const res = await request(server)
        .post(endpoint)
        .send({ email: "test@example.com" });

      expect(res.statusCode).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
      expect(res.body.message).toMatch("Save failed");
    }, 10000);

    it("should handle empty security questions array explicitly", async () => {
      User.findOne.mockResolvedValue(dummyUser);
      dummyUser.generateCryptoToken = jest
        .fn()
        .mockResolvedValue("fake-reset-token");
      dummyUser.securityQuestions = [];
      sendEmail.mockResolvedValue(true);
      const res = await request(server)
        .post(endpoint)
        .send({ email: dummyUser.email });
      expect(res.status).toBe(StatusCodes.OK);
      expect(res.body.message).toContain(
        "Your password reset request was successful. A reset link has been sent to your email address. Please check your inbox. To reset your password, you can either use the reset link or the OTP provided. The link will expire in a few minutes, so be sure to complete the process soon."
      );
      expect(res.body.data.resetUrl).toContain(
        "http://localhost:3000/api/v1/auth/reset-password/fake-reset-token"
      );
    }, 10000);
  });

  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should successfully handle password reset with OTP and email", async () => {
      jest.spyOn(User, "findOne").mockResolvedValue(dummyUser);
      generateOTP.mockReturnValue("654321");
      sendEmail.mockResolvedValue(true);
      const res = await request(server)
        .post(endpoint)
        .send({ email: "test@example.com" });

      expect(dummyUser.generateCryptoToken).toHaveBeenCalled();
      expect(dummyUser.save).toHaveBeenCalledTimes(2);
      expect(generateOTP).toHaveBeenCalled();
      expect(sendEmail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: "test@example.com",
          subject: "Password Reset Request",
          template: "forgotPassword",
          context: expect.objectContaining({
            userName: "Test User",
            resetUrl:
              "http://localhost:3000/api/v1/auth/reset-password/fake-reset-token",
            otp: "654321",
          }),
        })
      );
      expect(res.statusCode).toBe(StatusCodes.OK);
      expect(res.body.data.resetUrl).toBe(
        "http://localhost:3000/api/v1/auth/reset-password/fake-reset-token"
      );
      expect(res.body.message).toContain(
        "Your password reset request was successful. A reset link has been sent to your email address. Please check your inbox. To reset your password, you can either use the reset link or the OTP provided. The link will expire in a few minutes, so be sure to complete the process soon."
      );
    }, 10000);
  });
});

// ==============================
// Test Suite: Auth Controller - Verify Question
// ==============================
describe("Auth Controller - Verify Question", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/verify-security-question";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeAll(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    for (const field of verifyQuestionRequiredFields) {
      it(`should fail if ${field} is missing`, async () => {
        const payload = { ...dummyUser };
        delete payload[field];

        const res = await request(server).post(endpoint).send(payload);

        expect(res.status).toBe(StatusCodes.BAD_REQUEST);
        expect(res.body.message).toContain(
          `Security question verification failed: Missing required fields in request payload.`
        );
      });
    }
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should return unauthorized for an invalid or expired reset token", async () => {
      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockResolvedValue(false),
      });
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

    it("should return 401 if the security answer is incorrect", async () => {
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue({
          passwordResetToken: "validToken123",
          passwordResetTokenExpiration: Date.now() + 100000,
          compareSecurityAnswer: jest.fn().mockResolvedValue(false),
          save: jest.fn(),
        }),
      });
      const res = await request(server).post(endpoint).send({
        answer: "wrongAnswer",
        resetToken: "validToken",
        testQuestionId: "456",
      });
      expect(res.status).toBe(401);
      expect(res.body.message).toBe(
        "Security question verification failed: Incorrect answer provided."
      );
    });

    it("should return 200 and send reset URL and OTP on successful verification", async () => {
      const mockUser = {
        ...dummyUser,
        passwordResetToken: "validToken",
        passwordResetTokenExpiration: Date.now() + 60000,
        compareSecurityAnswer: jest.fn().mockResolvedValue(true),
        generateCryptoToken: jest.fn().mockResolvedValue("newResetToken"),
        save: jest.fn().mockResolvedValue(true),
      };
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(mockUser),
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
        "Security question verification successful. I have sent you a reset URL and OTP. You can use these to reset your password."
      );
      expect(sendEmail).toHaveBeenCalled();
      expect(logAudit).toHaveBeenCalled();
      expect(logActivity).toHaveBeenCalled();
    });

    it("should return 500 and log error if email sending fails", async () => {
      const mockUser = {
        ...dummyUser,
        compareSecurityAnswer: jest.fn().mockResolvedValue(true),
        passwordResetToken: "validToken",
        passwordResetTokenExpiration: Date.now() + 60000,
        generateCryptoToken: jest.fn().mockResolvedValue("newResetToken"),
        save: jest.fn().mockResolvedValue(true),
      };
      User.findOne = jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue(mockUser),
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
        "There was an issue with sending the email. Please try again later."
      );
    });

    it("should return 500 and log error if saving the user fails", async () => {
      const mockUser = {
        ...dummyUser,
        compareSecurityAnswer: jest.fn().mockResolvedValue(true),
        passwordResetToken: "validToken",
        passwordResetTokenExpiration: Date.now() + 60000,
        generateCryptoToken: jest.fn().mockResolvedValue("newResetToken"),
        save: jest.fn().mockRejectedValue(new Error("Database error")),
      };
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(mockUser),
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
      const mockUser = {
        ...dummyUser,
        passwordResetTokenExpiration: Date.now() + 60000,
        compareSecurityAnswer: jest.fn().mockResolvedValue(true),
        generateCryptoToken: jest
          .fn()
          .mockRejectedValue(new Error("Token generation failed")),
        save: jest.fn().mockResolvedValue(true),
      };

      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(mockUser),
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
  });

  // =============================================================================
  // Group: Successfully
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });
    it("should succeed with correct resetToken and answer", async () => {
      const hashedAnswer = await bcrypt.hash("blue", 10);
      const mockUser = {
        ...dummyUser,
        isVerified: true,
        isLocked: false,
        lockUntil: null,
        loginAttempts: 0,
        tokenExpirationTime: new Date(Date.now() + 3600 * 1000),
        twoFactorSecret: "secret",
        twoFactorEnabled: false,
        otp: "123456",
        otpExpiry: Date.now() + 15 * 60 * 1000,
        recaptchaToken: "dummy-recaptcha-token",
        passwordResetToken: "validToken",
        passwordResetTokenExpiration: new Date(Date.now() + 10 * 60 * 1000),
        securityQuestions: [
          {
            _id: "q123",
            question: "What is your favorite color?",
            answerHash: hashedAnswer,
          },
        ],
        resetOtpAttempts: jest.fn().mockResolvedValue(false),
        enableTwoFactor: jest
          .fn()
          .mockResolvedValue({ qrCodeDataURL: "fake-qr-code-url" }),
        compareOTP: jest.fn().mockResolvedValue(true),
        comparePassword: jest.fn().mockResolvedValue(true),
        isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
        verifyAndEnableTwoFactor: jest.fn().mockResolvedValue(true),
        incLoginAttempts: jest.fn().mockResolvedValue(undefined),
        resetLoginAttempts: jest.fn().mockResolvedValue(undefined),
        generateCryptoToken: jest.fn().mockResolvedValue("newResetToken"),
        compareSecurityAnswer: jest.fn().mockResolvedValue(true),
        save: jest.fn().mockResolvedValue(true),
      };

      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockResolvedValue(mockUser),
      });

      sendEmail.mockResolvedValue(true);

      const res = await request(server).post(endpoint).send({
        answer: "blue",
        resetToken: "validToken",
        testQuestionId: "q123",
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toBe(
        "Security question verification successful. I have sent you a reset URL and OTP. You can use these to reset your password."
      );
      expect(res.body.data.resetUrl).toContain(
        "http://localhost:3000/api/v1/auth/reset-password/newResetToken"
      );
    });
  });
});

// ==============================
// Test Suite: Auth Controller - Reset Password Using Token
// ==============================
describe("Auth Controller - Reset Password Using Token", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/reset-password";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeAll(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should fail if token is missing", async () => {
      const res = await request(server)
        .post(endpoint)
        .send({ newPassword: "Strong@123" });
      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toBe('Validation error: "token" is required');
    });

    it("should fail if newPassword is missing", async () => {
      const res = await request(server)
        .post(endpoint)
        .send({ token: "valid-token" });
      expect(res.status).toBe(StatusCodes.BAD_REQUEST);
      expect(res.body.message).toBe(
        'Validation error: "newPassword" is required'
      );
    });
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should return 401 Unauthorized if the token is invalid or expired", async () => {
      jest.spyOn(User, "findOne").mockImplementation(() => ({
        select: jest.fn().mockResolvedValue(null),
      }));

      const res = await request(server)
        .post("/api/v1/auth/reset-password")
        .send({ newPassword: "Strong@123", token: "invalid-or-expired-token" });

      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(res.body.message).toBe(
        "Password reset failed: The reset token is invalid or expired. Please request a new one."
      );

      jest.restoreAllMocks();
    }, 10000);

    it("should return 401 if token does not match any user", async () => {
      User.findOne.mockImplementationOnce(() => ({
        select: jest.fn().mockResolvedValue(null),
      }));

      const res = await request(server).post(endpoint).send({
        newPassword: "NewStrongPass@123",
        token: "valid-format-token",
      });
      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe(
        "Password reset failed: The reset token is invalid or expired. Please request a new one."
      );
    }, 10000);

    it("should reject reused passwords", async () => {
      const reusedPassword = "OldPassword@123";
      const user = await createTestUserWithPasswordHistory([
        "OldPassword@111",
        reusedPassword,
        "OldPassword@999",
      ]);
      const token = await generateValidPasswordResetToken(user);
      const res = await request(server)
        .post(endpoint)
        .send({ newPassword: reusedPassword, token: token });
      expect(res.status).toBe(401);
      expect(res.body.message).toBe(
        "Password reset failed: The reset token is invalid or expired. Please request a new one."
      );
    }, 10000);

    it("should reset password, clear token, increment token version, and return success", async () => {
      const oldPassword = "OldPassword123!";
      const newPassword = "Strong@123";
      const hashedOldPassword = await bcrypt.hash(oldPassword, 10);

      const token = "validToken";

      const mockUser = {
        ...dummyUser,
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
        select: jest.fn().mockResolvedValue(mockUser),
      });

      const res = await request(server)
        .post(endpoint)
        .send({ newPassword, token });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe(
        "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password."
      );
      expect(mockUser.password).toBe(newPassword);
      expect(mockUser.passwordResetToken).toBeUndefined();
      expect(mockUser.passwordResetTokenExpiration).toBeUndefined();
      expect(mockUser.tokenVersion).toBe(2);
      expect(mockUser.revokeTokens).toHaveBeenCalled();
      expect(mockUser.save).toHaveBeenCalled();
      expect(mockUser.passwordHistory.length).toBeGreaterThan(0);

      // Log assertions
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: mockUser._id,
          targetModel: "User",
          eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
        })
      );
      expect(logActivity).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser._id,
          action: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
        })
      );
    }, 10000);

    it("should trim passwordHistory to last 5 entries after password reset", async () => {
      const oldPasswords = [
        "oldHash@123",
        "oldHash@223",
        "oldHash@323",
        "oldHash@423",
        "oldHash@523",
        "oldHash@623",
      ];
      const token = "valid-token";
      const dummyUser = {
        _id: "user123",
        password: "currentHash@123",
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

      const res = await request(server).post(endpoint).send({
        newPassword: "Strong@123",
        token: token,
      });

      expect(res.statusCode).toBe(StatusCodes.OK);
      expect(dummyUser.password).toBe("Strong@123");
      expect(dummyUser.save).toHaveBeenCalled();
    }, 10000);

    it("should call revokeTokens on successful password reset", async () => {
      const oldPasswords = [
        "oldHash@2451",
        "oldHash@2452",
        "oldHash@2453",
        "oldHash@2454",
        "oldHash@2455",
      ];
      const token = "valid-token";
      const revokeTokensMock = jest.fn();
      const saveMock = jest.fn();

      const mockUser = {
        ...dummyUser,
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
        select: jest.fn().mockResolvedValue(mockUser),
      });

      const res = await request(server)
        .post(endpoint)
        .send({ newPassword: "Strong@123", token });

      expect(res.statusCode).toBe(StatusCodes.OK);
      expect(revokeTokensMock).toHaveBeenCalled();
      expect(saveMock).toHaveBeenCalled();
    }, 10000);

    it("should create audit and activity logs on successful password reset", async () => {
      const token = "valid-token";
      const newPassword = "Strong@ss123";

      const dummyUser = {
        _id: new mongoose.Types.ObjectId().toString(),
        password: "oldPasswordHash",
        passwordHistory: ["oldPassword@123", "oldPassword@223"],
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
        .post(endpoint)
        .send({ newPassword, token });

      expect(res.status).toBe(StatusCodes.OK);
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: dummyUser._id,
          targetId: dummyUser._id,
          targetModel: "User",
          eventType: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
          description:
            "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password.",
          req: expect.any(Object),
        })
      );
      expect(logActivity).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: dummyUser._id,
          action: logEvents.PASSWORD_RESET_WITH_TOKEN_SUCCESS,
          description:
            "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password.",
          req: expect.any(Object),
        })
      );
    }, 10000);

    it("should increment tokenVersion on successful password reset", async () => {
      const token = "valid-token";
      const newPassword = "Strong@123";

      const dummyUser = {
        _id: new mongoose.Types.ObjectId().toString(),
        password: "oldPasswordHash@345",
        passwordHistory: ["oldPassword@451", "oldPassword@782"],
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
        .post(endpoint)
        .send({ newPassword, token });

      expect(dummyUser.tokenVersion).toBe(2);
      expect(dummyUser.save).toHaveBeenCalledWith({
        validateBeforeSave: false,
      });

      expect(res.body.message).toBe(
        "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password."
      );

      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeNull();
    }, 10000);
  });

  // =============================================================================
  // Group: Successfully
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should successfully reset password", async () => {
      const userMock = {
        ...dummyUser,
        password: "oldHashedPassword@123",
        passwordHistory: ["oldHashedPassword@156", "oldHashedPassword@562"],
        passwordResetToken: "validToken",
        passwordResetTokenExpiration: Date.now() + 1000 * 60 * 60,
        tokenVersion: 1,
        isPasswordInHistory: jest.fn(),
        revokeTokens: jest.fn().mockResolvedValue(),
        save: jest.fn().mockResolvedValue(true),
      };

      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockResolvedValue(userMock),
      });

      userMock.isPasswordInHistory.mockResolvedValue(false);

      const res = await request(server)
        .post(endpoint)
        .send({ token: "valid-token", newPassword: "Strong@123" });

      expect(res.status).toBe(200);
      expect(res.body.message).toBe(
        "Password Reset Successful: Your password has been successfully reset using the provided token. You can now log in with your new password."
      );
      expect(userMock.passwordHistory).toContain("oldHashedPassword@123");
      expect(userMock.password).toBe("Strong@123");
      expect(userMock.passwordResetToken).toBeUndefined();
      expect(userMock.passwordResetTokenExpiration).toBeUndefined();
      expect(userMock.tokenVersion).toBe(2);
      expect(userMock.revokeTokens).toHaveBeenCalledTimes(1);
      expect(userMock.save).toHaveBeenCalledWith({ validateBeforeSave: false });
    });
  });
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

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    for (const field of resetPasswordOtpRequiredFields) {
      it(`should fail if ${field} is missing`, async () => {
        const payload = { ...dummyUser };
        delete payload[field];

        const res = await request(server).post(endpoint).send(payload);

        expect(res.status).toBe(StatusCodes.BAD_REQUEST);
        expect(res.body.message).toContain(`"${field}" is required`);
      });
    }

    it("should newPassword ≠ confirmPassword is missing", async () => {
      const payload = {
        ...defaultPayload,
        newPassword: "Password@123",
        confirmPassword: "WrongPassword@123",
      };
      const res = await request(server).post(endpoint).send(payload);
      expect(res.statusCode).toBe(400);
      expect(res.body.message).toContain(
        "Password reset failed: Passwords do not match."
      );
    }, 10000);
  });
  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

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
      expect(res.body.message).toBe("Password reset failed: User not found.");
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
      expect(res.body.message).toBe(
        "Password reset failed: Invalid or expired OTP."
      );
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
        newPassword: "newPassword@123",
        confirmPassword: "newPassword@123",
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
        newPassword: "newPassword@123",
        confirmPassword: "newPassword@123",
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
        newPassword: "newPassword@123",
        confirmPassword: "newPassword@123",
      });
      expect(res.status).toBe(500);
      expect(res.body.message).toBe("Audit log error");
    }, 10000);
  });
  // =============================================================================
  // Group: Successfully
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeAll(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should reset password successfully with valid email, OTP, and matching passwords", async () => {
      const dummyUser = {
        _id: "user123",
        email: "test@example.com",
        compareOTP: jest.fn().mockResolvedValue(true),
        save: jest.fn().mockResolvedValue(true),
        otp: "123456",
        otpExpiry: new Date(Date.now() + 10 * 60 * 1000),
      };

      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockResolvedValue(dummyUser),
      });

      logAudit.mockReturnValue(true);
      logActivity.mockReturnValue(true);

      const res = await request(server).post(endpoint).send({
        email: "test@example.com",
        otp: "123456",
        newPassword: "testPassword@123",
        confirmPassword: "testPassword@123",
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toContain(
        "Password Reset Successful: Your password has been successfully reset using the provided otp. You can now log in with your new password."
      );
    }, 10000);
  });
});

// ==============================
// Test Suite: Auth Controller - Resend OTP
// ==============================
describe("Auth Controller - Resend OTP", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/resend-otp";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

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
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
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
      expect(res.body.message).toBe(
        "OTP reset failed: If an account with this email exists, an OTP has been sent. Please check your inbox."
      );
    });

    it("should not send OTP when user not found", async () => {
      User.findOne.mockReturnValue({
        select: jest.fn().mockResolvedValue(null),
      });
      const res = await request(server)
        .post(endpoint)
        .send({ email: "nonexistent@example.com" });
      expect(res.status).toBe(StatusCodes.OK);
      expect(res.body.message).toBe(
        "OTP reset failed: If an account with this email exists, an OTP has been sent. Please check your inbox."
      );
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
      expect(res.body.message).toBe(
        "OTP verification successful: If an account exists with this email, a new OTP has been sent for verification. Please check your inbox."
      );
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
      expect(res.body.message).toBe(
        "Failed to update user with OTP. Please try again."
      );
      expect(generateOTP).toHaveBeenCalled();
      expect(dummyUser.otp).toBe("123456");
      expect(dummyUser.otpExpiry).toBeInstanceOf(Date);
      expect(dummyUser.otpAttempts).toBe(0);
      expect(dummyUser.save).toHaveBeenCalledWith({
        validateBeforeSave: false,
      });
      expect(sendEmail).not.toHaveBeenCalled();
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: logEvents.OTP_RESET_REQUEST_FAILED,
          description: expect.stringContaining(
            "Failed to update user with OTP"
          ),
        })
      );
      expect(logActivity).toHaveBeenCalledWith(
        expect.objectContaining({
          action: logEvents.OTP_RESET_REQUEST_FAILED,
          description: expect.stringContaining(
            "Failed to update user with OTP"
          ),
        })
      );
    });

    it("should handle non-error rejection from sendEmail", async () => {
      const email = "test@example.com";

      const dummyUser = {
        _id: "user123",
        email,
        fullName: "Test User",
        isVerified: false,
        otp: null,
        otpExpiry: null,
        otpAttempts: 3,
        save: jest.fn().mockImplementation(function () {
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
          this.otp = undefined;
          this.otpExpiry = undefined;
          this.otpCleared = true;
          return Promise.resolve(true);
        });

      const res = await request(server).post(endpoint).send({ email });

      expect(res.status).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
      expect(res.body.message).toBe("Failed to send verification email.");

      expect(generateOTP).toHaveBeenCalled();
      expect(dummyUser.save).toHaveBeenCalledTimes(2);

      expect(dummyUser.otp).toBeUndefined();
      expect(dummyUser.otpExpiry).toBeUndefined();

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

  // =============================================================================
  // Group: Successfully
  // =============================================================================
  describe("Successfully", () => {
    it("should handle the successfully resendOTP logic", async () => {
      jest.spyOn(User, "findOne").mockReturnValue({
        select: jest.fn().mockResolvedValue({
          ...dummyUser,
          isVerified: false,
          otp: "123456",
          otpExpiry: new Date(Date.now() + 10 * 60 * 1000),
          otpAttempts: 0,
          save: dummyUser.save,
        }),
      });

      sendEmail.mockResolvedValue(true);

      const res = await request(server)
        .post(endpoint)
        .send({ email: dummyUser.email });

      console.log(res.body);
      console.log(res.status);

      expect(res.status).toBe(StatusCodes.OK);
      expect(res.body.message).toBe(
        "OTP verification successful: If an account exists with this email, a new OTP has been sent for verification. Please check your inbox."
      );

      expect(User.findOne).toHaveBeenCalledWith({ email: dummyUser.email });
      expect(sendEmail).toHaveBeenCalled();
      expect(dummyUser.save).toHaveBeenCalled();
      expect(logAudit).toHaveBeenCalled();
      expect(logActivity).toHaveBeenCalled();
    });
  });
});

// ==============================
// Test Suite: Auth Controller - Logout User
// ==============================
describe("Auth Controller - Logout User", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/logout";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
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
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should fail logout if token is expired but within grace period", async () => {
      const userId = new mongoose.Types.ObjectId().toString();

      const expiredTokenPayload = {
        id: userId,
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
        _id: userId,
        isTokenExpiredGracefully: jest.fn().mockReturnValue(true),
      };

      jest.spyOn(User, "findById").mockResolvedValue(mockUser);

      const res = await request(server)
        .get(endpoint)
        .set("Cookie", [`refreshToken=${expiredToken}`]);

      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(res.body.message).toBe(
        "Logout attempt failed: Token expired but within grace period."
      );
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: userId,
          eventType: logEvents.LOGOUT_FAILED,
          description:
            "Logout attempt failed: Token expired but within grace period.",
        })
      );
      expect(logActivity).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: userId,
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

      expect(res.statusCode).toBe(StatusCodes.UNAUTHORIZED);
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

      expect(res.statusCode).toBe(StatusCodes.NOT_FOUND);
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

      jest.spyOn(Session, "findOneAndUpdate").mockResolvedValue(null);

      const res = await request(server)
        .get(endpoint)
        .set("Cookie", [
          `refreshToken=${refreshToken}`,
          `accessToken=${accessToken}`,
        ]);

      expect(res.statusCode).toBe(StatusCodes.NOT_FOUND);
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
  });

  // =============================================================================
  // Group: Successfully
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should successfully log out user", async () => {
      const userId = new mongoose.Types.ObjectId();

      const mockUser = {
        _id: userId,
        email: "test@example.com",
        tokenVersion: 0,
        twoFactorEnabled: true,
        revokeTokens: jest.fn().mockResolvedValue(true),
        hashSessionToken: jest
          .fn()
          .mockImplementation((token) =>
            Promise.resolve(hashedSessionToken(token))
          ),
        save: jest.fn().mockResolvedValue(true),
        isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
      };

      const hashedToken = hashedSessionToken(refreshToken);

      const mockSession = {
        _id: new mongoose.Types.ObjectId(),
        userId: userId,
        refreshTokenHash: hashedToken,
        isActive: true,
        save: jest.fn().mockResolvedValue(true),
      };

      jest.spyOn(jwt, "verify").mockImplementation(() => ({
        id: userId.toString(),
        exp: Math.floor(Date.now() / 1000) + 3600,
      }));

      jest
        .spyOn(User, "findById")
        .mockImplementation((id) =>
          id.toString() === userId.toString()
            ? Promise.resolve(mockUser)
            : Promise.resolve(null)
        );

      jest
        .spyOn(Session, "findOneAndUpdate")
        .mockImplementation((query) =>
          query.userId.toString() === userId.toString() &&
          query.refreshTokenHash === hashedToken
            ? Promise.resolve({ ...mockSession, isActive: false })
            : Promise.resolve(null)
        );

      jest.spyOn(TokenBlacklist, "create").mockImplementation((data) =>
        Promise.resolve({
          _id: new mongoose.Types.ObjectId(),
          ...data,
          expiresAt: new Date(),
        })
      );

      const res = await request(server)
        .get(endpoint)
        .set("Cookie", [`refreshToken=${refreshToken}`]);

      expect(res.status).toBe(StatusCodes.OK);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain("Logged out successfully.");

      expect(jwt.verify).toHaveBeenCalledWith(refreshToken, refreshTokenSecret);
      expect(User.findById).toHaveBeenCalledWith(userId.toString());
      expect(mockUser.revokeTokens).toHaveBeenCalled();
      expect(Session.findOneAndUpdate).toHaveBeenCalledWith(
        {
          userId: userId.toString(),
          refreshTokenHash: hashedToken,
          isActive: true,
        },
        { isActive: false },
        { new: true }
      );
    }, 10000);
  });
});

// ==============================
// Test Suite: Auth Controller - Refresh Token
// ==============================
describe("Auth Controller - Refresh Token", () => {
  // =============================================================================
  // Constants
  // =============================================================================
  const endpoint = "/api/v1/auth/refresh-token";

  // =============================================================================
  // Setup & Teardown
  // =============================================================================
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // Group: Validation Failures
  // =============================================================================
  describe("Validation Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should throw error when refresh token is missing", async () => {
      const res = await request(server)
        .get(endpoint)
        .set("Cookie", "")
        .send({});

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
  });

  // =============================================================================
  // Group: Edge Cases Failures
  // =============================================================================
  describe("Edge Cases Failures", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should return 401 when rotateTokens fails due to invalid token", async () => {
      jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
      jest
        .spyOn(User, "rotateTokens")
        .mockRejectedValue(new Error("Invalid refresh token"));
      const res = await request(server)
        .get(endpoint)
        .set("Cookie", `refreshToken=${refreshToken}`)
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
      expect(User.rotateTokens).toHaveBeenCalledWith(
        refreshToken,
        expect.any(Object)
      );
    }, 10000);

    it("should return 404 when user is not found in rotateTokens", async () => {
      jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
      jest
        .spyOn(User, "rotateTokens")
        .mockRejectedValue(new Error("User not found."));

      const res = await request(server)
        .get(endpoint)
        .set("Cookie", `refreshToken=${refreshToken}`)
        .send({});

      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
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
      expect(User.rotateTokens).toHaveBeenCalledWith(
        refreshToken,
        expect.any(Object)
      );
    }, 10000);

    it("should return 401 when new refresh token is in graceful expiration period", async () => {
      jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
      jest.spyOn(User, "rotateTokens").mockResolvedValue(dummyToken);
      jest.spyOn(jwt, "decode").mockReturnValue({
        id: dummyUser._id,
        exp: Math.floor(Date.now() / 1000),
      });
      const user = {
        _id: dummyUser._id,
        isTokenExpiredGracefully: jest.fn().mockReturnValue(true),
      };
      jest.spyOn(User, "findById").mockResolvedValue(user);

      const res = await request(server)
        .get(endpoint)
        .set("Cookie", `refreshToken=${refreshToken}`)
        .send({});

      expect(res.status).toBe(StatusCodes.UNAUTHORIZED);
      expect(res.body.message).toBe(
        "Refresh Token Failed: Token expired but within grace period."
      );
      expect(logSession).toHaveBeenCalledWith(
        expect.objectContaining({
          user,
          refreshToken: dummyToken.refreshToken,
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
      expect(User.rotateTokens).toHaveBeenCalledWith(
        refreshToken,
        expect.any(Object)
      );
      expect(User.findById).toHaveBeenCalledWith(dummyUser._id);
      expect(user.isTokenExpiredGracefully).toHaveBeenCalledWith(
        expect.any(Number)
      );
    }, 10000);
  });

  // =============================================================================
  // Group: Successfully
  // =============================================================================
  describe("Successfully", () => {
    // =============================================================================
    // Setup & Teardown
    // =============================================================================
    beforeEach(() => {
      jest.clearAllMocks();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it("should refresh token successfully when token is in cookies", async () => {
      const mockUser = {
        _id: dummyUser._id,
        isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
      };

      jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);

      User.rotateTokens = jest.fn().mockResolvedValue({
        user: mockUser,
        dummyToken,
      });

      jest.spyOn(User, "findById").mockResolvedValue(mockUser);

      jest.spyOn(jwt, "decode").mockReturnValue({
        id: "user-id",
        exp: Date.now() / 1000 + 3600,
      });

      logSession.mockResolvedValue(true);
      logAudit.mockResolvedValue(true);
      logActivity.mockResolvedValue(true);

      const res = await request(server)
        .get(endpoint)
        .set("Cookie", `refreshToken=${refreshToken}`)
        .send({});

      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: logEvents.REFRESH_TOKEN_SUCCESS,
          description:
            "Refresh Token successful: Token refreshed successfully.",
        })
      );

      expect(logActivity).toHaveBeenCalledWith(
        expect.objectContaining({
          action: logEvents.REFRESH_TOKEN_SUCCESS,
          description:
            "Refresh Token successful: Token refreshed successfully.",
        })
      );

      expect(res.status).toBe(StatusCodes.OK);
      expect(res.body.message).toBe(
        "Refresh Token successful: Token refreshed successfully."
      );
    }, 10000);

    it("should refresh token successfully when token is in body", async () => {
      jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
      User.rotateTokens = jest.fn().mockResolvedValue(dummyToken);
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
        .send({ refreshToken: refreshToken });
      expect(res.status).toBe(StatusCodes.OK);
      expect(res.body.message).toBe(
        "Refresh Token successful: Token refreshed successfully."
      );
      const cookies = res.headers["set-cookie"];
      expect(cookies).toEqual(
        expect.arrayContaining([
          expect.stringContaining(`accessToken=${dummyToken.accessToken}`),
          expect.stringContaining(`refreshToken=${dummyToken.refreshToken}`),
        ])
      );
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: logEvents.REFRESH_TOKEN_SUCCESS,
          description:
            "Refresh Token successful: Token refreshed successfully.",
        })
      );
      expect(logActivity).toHaveBeenCalledWith(
        expect.objectContaining({
          action: logEvents.REFRESH_TOKEN_SUCCESS,
          description:
            "Refresh Token successful: Token refreshed successfully.",
        })
      );
      expect(logSession).toHaveBeenCalledWith(
        expect.objectContaining({
          user: expect.objectContaining({ _id: "user-id" }),
          refreshToken: dummyToken.refreshToken,
        })
      );
    }, 10000);

    it("should return 200 and new tokens when refresh is successful", async () => {
      jest.spyOn(TokenBlacklist, "findOne").mockResolvedValue(null);
      jest.spyOn(User, "rotateTokens").mockResolvedValue(dummyToken);
      jest.spyOn(jwt, "decode").mockReturnValue({
        id: dummyUser._id,
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      const user = {
        _id: dummyUser._id,
        isTokenExpiredGracefully: jest.fn().mockReturnValue(false),
      };
      jest.spyOn(User, "findById").mockResolvedValue(user);
      const res = await request(server)
        .get(endpoint)
        .set("Cookie", `refreshToken=${refreshToken}`)
        .send({});
      expect(res.status).toBe(StatusCodes.OK);
      expect(res.body.message).toBe(
        "Refresh Token successful: Token refreshed successfully."
      );
      expect(res.headers["set-cookie"]).toEqual(
        expect.arrayContaining([
          expect.stringContaining(`accessToken=${dummyToken.accessToken}`),
          expect.stringContaining(`refreshToken=${dummyToken.refreshToken}`),
        ])
      );
      expect(logSession).toHaveBeenCalledWith(
        expect.objectContaining({
          user,
          refreshToken: dummyToken.refreshToken,
        })
      );
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: logEvents.REFRESH_TOKEN_SUCCESS,
          description:
            "Refresh Token successful: Token refreshed successfully.",
        })
      );
      expect(logActivity).toHaveBeenCalledWith(
        expect.objectContaining({
          action: logEvents.REFRESH_TOKEN_SUCCESS,
          description:
            "Refresh Token successful: Token refreshed successfully.",
        })
      );
      expect(User.rotateTokens).toHaveBeenCalledWith(
        refreshToken,
        expect.any(Object)
      );
      expect(User.findById).toHaveBeenCalledWith(dummyUser._id);
      expect(user.isTokenExpiredGracefully).toHaveBeenCalledWith(
        expect.any(Number)
      );
    }, 10000);
  });
});
