import Joi from "joi";

export const registerUserSchema = Joi.object({
  fullName: Joi.string().trim().min(2).max(100).required(),
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required(),
  phone: Joi.string()
    .pattern(/^[0-9]{10,15}$/)
    .required()
    .messages({
      "string.pattern.base": "Phone must be a valid number with 10–15 digits.",
    }),
  userName: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string()
    .min(8)
    .max(64)
    .pattern(/[a-z]/, "lowercase")
    .pattern(/[A-Z]/, "uppercase")
    .pattern(/[0-9]/, "number")
    .pattern(/[^a-zA-Z0-9]/, "special")
    .required()
    .messages({
      "string.pattern.name":
        "Password must contain at least one {#name} character.",
    }),
  recaptchaToken: Joi.string().required(),
  securityQuestions: Joi.array()
    .items(
      Joi.object({
        question: Joi.string().required(),
        answer: Joi.string().required(),
      })
    )
    .optional(),
});

export const loginUserSchema = Joi.object({
  email: Joi.string().email().lowercase().trim(),
  phone: Joi.string()
    .pattern(/^\+?[1-9]\d{1,14}$/)
    .message("Phone must be a valid E.164 format"),
  password: Joi.string().required().messages({
    "string.empty": "Password is required.",
  }),
  twoFactorCode: Joi.string().length(6).pattern(/^\d+$/).required().messages({
    "string.empty": "Two-Factor Authentication code is required.",
    "string.length": "2FA code must be 6 digits.",
    "string.pattern.base": "2FA code must contain only digits.",
  }),
})
  .or("email", "phone")
  .messages({
    "object.missing": "Either email or phone is required.",
  });

export const verifyEmailSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required(),
  otp: Joi.string().required(),
});

export const resetPasswordTokenSchema = Joi.object({
  newPassword: Joi.string()
    .min(8)
    .max(64)
    .pattern(/[a-z]/, "lowercase")
    .pattern(/[A-Z]/, "uppercase")
    .pattern(/[0-9]/, "number")
    .pattern(/[^a-zA-Z0-9]/, "special")
    .required()
    .messages({
      "string.pattern.name":
        "Password must contain at least one {#name} character.",
    })
    .required(),
  token: Joi.string().required(),
});

export const resetPasswordOtpSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required(),
  otp: Joi.string().required(),
  confirmPassword: Joi.string()
    .min(8)
    .max(64)
    .pattern(/[a-z]/, "lowercase")
    .pattern(/[A-Z]/, "uppercase")
    .pattern(/[0-9]/, "number")
    .pattern(/[^a-zA-Z0-9]/, "special")
    .required()
    .messages({
      "string.pattern.name":
        "Password must contain at least one {#name} character.",
    })
    .required(),
  newPassword: Joi.string()
    .min(8)
    .max(64)
    .pattern(/[a-z]/, "lowercase")
    .pattern(/[A-Z]/, "uppercase")
    .pattern(/[0-9]/, "number")
    .pattern(/[^a-zA-Z0-9]/, "special")
    .required()
    .messages({
      "string.pattern.name":
        "Password must contain at least one {#name} character.",
    })
    .required(),
});
