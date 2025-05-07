// Database
import mongoose from "mongoose";
import { MongoServerError } from "mongodb";

// External Package
import { StatusCodes } from "http-status-codes";

// Utils
import ApiError from "../utils/apiError.js";
import ApiResponse from "../utils/apiResponse.js";

// Logger
import logger from "../logger/logger.js";

const errorHandler = (err, req, res, next) => {
  if (process.env.NODE_ENV === "development") {
    logger.error(err);
  }

  let customError = err;

  // Invalid ObjectId
  if (err instanceof mongoose.Error.CastError) {
    customError = new ApiError(
      `Invalid ${err.path}: ${err.value}`,
      StatusCodes.BAD_REQUEST
    );
  }

  // Mongoose Validation Errors
  else if (err instanceof mongoose.Error.ValidationError) {
    const messages = Object.values(err.errors).map((e) => e.message);
    customError = new ApiError(messages.join(", "), StatusCodes.BAD_REQUEST);
  }

  // Duplicate Key Error
  else if (err.code === 11000 || err instanceof MongoServerError) {
    const field = Object.keys(err.keyValue || {})[0];
    const value = err.keyValue?.[field];
    const msg =
      field && value
        ? `Duplicate value for field "${field}": "${value}"`
        : "Duplicate key error";
    customError = new ApiError(msg, StatusCodes.BAD_REQUEST);
  }

  // Database Connection Errors
  else if (
    err.message?.includes("failed to connect to server") ||
    err.message?.includes("ECONNREFUSED")
  ) {
    customError = new ApiError(
      "Database connection failed. Please try again later.",
      StatusCodes.SERVICE_UNAVAILABLE
    );
  }

  // Query Timeout
  else if (err.message?.includes("timed out")) {
    customError = new ApiError(
      "Database request timed out.",
      StatusCodes.REQUEST_TIMEOUT
    );
  }

  // General Mongo/Mongoose Error Catch
  else if (
    err.name?.includes("Mongo") ||
    err instanceof mongoose.Error ||
    err instanceof MongoServerError
  ) {
    if (!customError.statusCode || customError.statusCode === 500) {
      customError = new ApiError(
        "A database error occurred. Please try again.",
        StatusCodes.INTERNAL_SERVER_ERROR
      );
    }
  }

  const statusCode =
    customError.statusCode || StatusCodes.INTERNAL_SERVER_ERROR;
  const message = customError.message || "Internal Server Error";

  return new ApiResponse(
    statusCode,
    {
      error: customError.name,
      ...(process.env.NODE_ENV === "development" && {
        stack: customError.stack,
      }),
    },
    message
  ).send(res);
};

export default errorHandler;
