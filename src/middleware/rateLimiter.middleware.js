// ==============================
// External Packages
// ==============================
import rateLimit from "express-rate-limit";

// Rate limiting for registration (less frequent attempts)
export const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 5, // Max 5 attempts per hour
  message: "Too many registration attempts, please try again later.",
});

// Rate limiting for login (stricter due to security risks)
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minute window
  max: 3, // Max 3 attempts per 15 minutes
  message: "Too many login attempts, please try again later.",
});

// Rate limiting for forgot password (also fairly sensitive)
export const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minute window
  max: 3, // Max 3 attempts per 15 minutes
  message: "Too many password reset attempts, please try again later.",
});

export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});
