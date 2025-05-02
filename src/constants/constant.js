// ==============================
// Server Configuration
// ==============================
export const port = process.env.PORT;

// ==============================
// Database Configuration
// ==============================
export const mongoUrl = process.env.MONGO_URI;
export const mongoDb = process.env.MONGO_DB;

// ==============================
// Cloudinary Configuration
// ==============================
export const cloudinaryName = process.env.CLOUDINARY_NAME;
export const cloudinaryApiKey = process.env.CLOUDINARY_API_KEY;
export const cloudinaryApiSecret = process.env.CLOUDINARY_API_SECRET;

// ==============================
// Google Recapture Configuration
// ==============================

export const GoggleSiteKey = process.env.GOOGLE_SITE_KEY;
export const GoggleSecretKey = process.env.GOOGLE_SECRET_KEY;

// ==============================
// JWT Configuration
// ==============================
export const accessTokenSecret = process.env.JWT_ACCESS_TOKEN_SECRET;
export const refreshTokenSecret = process.env.JWT_REFRESH_TOKEN_SECRET;

// Used with jwt.sign (e.g. "15m", "7d")
export const accessTokenExpiresIn =
  process.env.JWT_ACCESS_TOKEN_EXPIRESIN || "15m";
export const refreshTokenExpiresIn =
  process.env.JWT_REFRESH_TOKEN_EXPIRESIN || "7d";

// Used for date calculations
export const accessTokenTTL = 15 * 60 * 1000;
export const refreshTokenTTL = 7 * 24 * 60 * 60 * 1000;

// ==============================
// Token Blacklist Schema
// ==============================
export const blacklistTokenTTL = refreshTokenTTL; // Match refresh lifespan

// ==============================
// Session Secret Key
// ==============================
export const SessionSecretKey = process.env.SESSION_SECRET_KEY;

// ==============================
// Security & Auth
// ==============================
export const salt = 15;

// OTP
export const otpExpiresInMinutes = 10;
export const otpExpiresInMs = otpExpiresInMinutes * 60 * 1000;

// Session
export const sessionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

// Password Reset
export const passwordResetTokenTTL = 1 * 60 * 60 * 1000;

// Login Throttling
export const maxLoginAttempt = 5;
export const lockTime = 15 * 60 * 1000;

// ==============================
// Email Credentials
// ==============================
export const emailId = process.env.USER_EMAIL_ID;
export const emailPassword = process.env.USER_EMAIL_PASSWORD;

// ==============================
// Client Url
// ==============================
export const clientUrl = process.env.CLIENT_URL;

// ==============================
// Cookie Options
// ==============================
export const options = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 24 * 60 * 60 * 1000, // 1 day
};

// ==============================
// Example Use Timestamp (for testing or static expiration only)
// ==============================
export const expireTime = Date.now() + 15 * 60 * 1000;

// ==============================
// Token
// ==============================
export const tokenGracePeriod = 5 * 60 * 1000;
