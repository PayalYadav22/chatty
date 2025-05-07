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
// Session Secret Key
// ==============================
export const SessionSecretKey = process.env.SESSION_SECRET_KEY;

// ==============================
// JWT Configuration
// ==============================
export const accessTokenSecret = process.env.JWT_ACCESS_TOKEN_SECRET; // JWT access token secret
export const refreshTokenSecret = process.env.JWT_REFRESH_TOKEN_SECRET; // JWT refresh token secret

// Used with jwt.sign (e.g. "15m", "7d")
export const accessTokenExpiresIn =
  process.env.JWT_ACCESS_TOKEN_EXPIRESIN || "15m";
export const refreshTokenExpiresIn =
  process.env.JWT_REFRESH_TOKEN_EXPIRESIN || "7d";
