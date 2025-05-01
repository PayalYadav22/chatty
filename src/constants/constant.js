export const port = process.env.PORT;

export const mongoUrl = process.env.MONGO_URI;
export const mongoDb = process.env.MONGO_DB;

export const cloudinaryName = process.env.CLOUDINARY_NAME;
export const cloudinaryApiKey = process.env.CLOUDINARY_API_KEY;
export const cloudinaryApiSecret = process.env.CLOUDINARY_API_SECRET;

export const accessTokenSecret = process.env.JWT_ACCESS_TOKEN_SECRET;
export const accessTokenExpiresIn = process.env.JWT_ACCESS_TOKEN_EXPIRESIN;
export const refreshTokenSecret = process.env.JWT_REFRESH_TOKEN_SECRET;
export const refreshTokenExpiresIn = process.env.JWT_REFRESH_TOKEN_EXPIRESIN;

export const emailId = process.env.USER_EMAIL_ID;
export const emailPassword = process.env.USER_EMAIL_PASSWORD;

export const expireTime = Date.now() + 15 * 60 * 1000;

export const salt = 15;

export const options = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 24 * 60 * 60 * 1000,
};

export const maxLoginAttempt = 5;
export const lockTime = 15 * 60 * 1000;
