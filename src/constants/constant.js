// ==============================
// Server Configuration
// ==============================
export const port = process.env.PORT; // Server port

// ==============================
// Database Configuration
// ==============================
export const mongoUrl = process.env.MONGO_URI; // MongoDB connection URI
export const mongoDb = process.env.MONGO_DB; // MongoDB database name

// ==============================
// Cloudinary Configuration
// ==============================
export const cloudinaryName = process.env.CLOUDINARY_NAME; // Cloudinary cloud name
export const cloudinaryApiKey = process.env.CLOUDINARY_API_KEY; // Cloudinary API key
export const cloudinaryApiSecret = process.env.CLOUDINARY_API_SECRET; // Cloudinary API secret

// ==============================
// Google Recaptcha Configuration
// ==============================
export const GoggleSiteKey = process.env.GOOGLE_SITE_KEY; // Google reCAPTCHA site key
export const GoggleSecretKey = process.env.GOOGLE_SECRET_KEY; // Google reCAPTCHA secret key

// ==============================
// JWT Configuration
// ==============================
export const accessTokenSecret = process.env.JWT_ACCESS_TOKEN_SECRET; // JWT access token secret
export const refreshTokenSecret = process.env.JWT_REFRESH_TOKEN_SECRET; // JWT refresh token secret

// Used with jwt.sign (e.g. "15m", "7d")
export const accessTokenExpiresIn =
  process.env.JWT_ACCESS_TOKEN_EXPIRESIN || "15m"; // Access token expiry (string)
export const refreshTokenExpiresIn =
  process.env.JWT_REFRESH_TOKEN_EXPIRESIN || "7d"; // Refresh token expiry (string)

// Used for date calculations
export const accessTokenTTL = 15 * 60 * 1000; // 15 minutes in ms
export const refreshTokenTTL = 7 * 24 * 60 * 60 * 1000; // 7 days in ms

// ==============================
// Token Blacklist Schema
// ==============================
export const blacklistTokenTTL = refreshTokenTTL; // Match refresh lifespan for blacklist

// ==============================
// Session Secret Key
// ==============================
export const SessionSecretKey = process.env.SESSION_SECRET_KEY; // Session encryption secret

// ==============================
// Security & Auth
// ==============================
export const salt = 15; // Salt rounds for hashing

// OTP
export const otpExpiresInMinutes = 10; // OTP expiry in minutes
export const otpExpiresInMs = otpExpiresInMinutes * 60 * 1000; // OTP expiry in milliseconds

// Session
export const sessionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // Session expiry: 30 days

// Password Reset
export const passwordResetTokenTTL = 1 * 60 * 60 * 1000; // Password reset token TTL: 1 hour

// Login Throttling
export const maxLoginAttempt = 5; // Max allowed login attempts
export const lockTime = 15 * 60 * 1000; // Account lock time: 15 minutes

// ==============================
// Email Credentials
// ==============================
export const emailId = process.env.USER_EMAIL_ID; // Email account ID
export const emailPassword = process.env.USER_EMAIL_PASSWORD; // Email account password

// ==============================
// Client Url
// ==============================
export const clientUrl = process.env.CLIENT_URL; // Frontend base URL

// ==============================
// Cookie Options
// ==============================
export const options = {
  httpOnly: true, // Prevent client-side JS access to cookie
  secure: process.env.NODE_ENV === "production", // Use secure cookies in production
  sameSite: "strict", // Prevent CSRF
  maxAge: 24 * 60 * 60 * 1000, // 1 day in ms
};

// ==============================
// Example Use Timestamp (for testing or static expiration only)
// ==============================
export const expireTime = Date.now() + 15 * 60 * 1000; // Current time + 15 mins

// ==============================
// Token
// ==============================
export const tokenGracePeriod = 5 * 60 * 1000; // Token grace period: 5 minutes

// ==============================
// Activity Login
// ==============================
export const logEvents = {
  // Authentication Methods
  REGISTER_SUCCESS: "REGISTER_SUCCESS",
  REGISTER_FAILED: "REGISTER_FAILED",

  // Email Verified
  VERIFIED_EMAIL_FAILED: "VERIFIED_EMAIL_FAILED",
  VERIFIED_EMAIL_SUCCESS: "VERIFIED_EMAIL_SUCCESS",

  // Login
  LOGIN_FAILED: "LOGIN_FAILED",
  LOGIN_SUCCESS: "LOGIN_SUCCESS",

  // Forgot Password
  FORGOT_PASSWORD_FAILED: "FORGOT_PASSWORD_FAILED",
  FORGOT_PASSWORD_SUCCESS: "FORGOT_PASSWORD_SUCCESS",

  // Question Prompted
  PASSWORD_RESET_SECURITY_QUESTION_PROMPTED:
    "PASSWORD_RESET_SECURITY_QUESTION_PROMPTED",

  // Password Reset Request
  PASSWORD_RESET_REQUEST_FAILED: "PASSWORD_RESET_REQUEST_FAILED",
  PASSWORD_RESET_REQUEST_SUCCESS: "PASSWORD_RESET_REQUEST_SUCCESS",

  // Reset Password with Token
  PASSWORD_RESET_WITH_TOKEN_FAILED: "PASSWORD_RESET_WITH_TOKEN_FAILED",
  PASSWORD_RESET_WITH_TOKEN_SUCCESS: "PASSWORD_RESET_WITH_TOKEN_SUCCESS",

  // Reset Password with OTP
  PASSWORD_RESET_WITH_OTP_FAILED: "PASSWORD_RESET_WITH_OTP_FAILED",
  PASSWORD_RESET_WITH_OTP_SUCCESS: "PASSWORD_RESET_WITH_OTP_SUCCESS",

  // OTP Reset Request
  OTP_RESET_REQUEST_FAILED: "OTP_RESET_REQUEST_FAILED",
  OTP_RESET_REQUEST_SUCCESS: "OTP_RESET_REQUEST_SUCCESS",

  // Logout
  LOGOUT_FAILED: "LOGOUT_FAILED",
  LOGOUT_SUCCESS: "LOGOUT_SUCCESS",

  // Refresh Token
  REFRESH_TOKEN_FAILED: "REFRESH_TOKEN_FAILED",
  REFRESH_TOKEN_SUCCESS: "REFRESH_TOKEN_SUCCESS",

  // Token Black List
  TOKEN_BLACK_LIST_READ: "TOKEN_BLACK_LIST_READ",
  TOKEN_BLACK_LIST_REMOVE_FAILED: "TOKEN_BLACK_LIST_REMOVE_FAILED",
  TOKEN_BLACK_LIST_REMOVE_SUCCESS: "TOKEN_BLACK_LIST_REMOVE_SUCCESS",

  // Session List
  SESSION_LIST: "SESSION_LIST",
  SESSION_CREATE_FAILED: "SESSION_CREATE_FAILED",
  SESSION_CREATE_SUCCESS: "SESSION_CREATE_SUCCESS",
  SESSION_VIEW_FAILED: "SESSION_VIEW_FAILED",
  SESSION_VIEW_SUCCESS: "SESSION_VIEW_SUCCESS",
  SESSION_INVALIDATION_FAILED: "SESSION_INVALIDATION_FAILED",
  SESSION_INVALIDATION_SUCCESS: "SESSION_INVALIDATION_SUCCESS",
  SESSION_DELETE_FAILED: "SESSION_DELETE_FAILED",
  SESSION_DELETE_SUCCESS: "SESSION_DELETE_SUCCESS",
  SESSION_COUNT_FAILED: "SESSION_COUNT_FAILED",
  SESSION_COUNT_SUCCESS: "SESSION_COUNT_SUCCESS",
  LOGOUT_ALL_SESSIONS: "LOGOUT_ALL_SESSIONS",

  // User Profile Actions
  VIEW_PROFILE: "VIEW_PROFILE",
  UPDATE_PROFILE: "UPDATE_PROFILE",
  UPDATE_AVATAR: "UPDATE_AVATAR",
  DELETE_AVATAR: "DELETE_AVATAR",
  CHANGE_PASSWORD: "CHANGE_PASSWORD",
  DELETE_ACCOUNT: "DELETE_ACCOUNT",
  LIST_PROFILE: "LIST_PROFILE",
};
