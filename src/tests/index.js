// ==============================
// Env Config
// ==============================
import "../config/env.config.js";

// ==============================
// External Packages
// ==============================
import mongoose from "mongoose";

// ==============================
// Database Connection
// ==============================
import connectDB from "./config/db.config.js";

// ==============================
// Constant
// ==============================
import { mongoUrl, mongoDb } from "./constants/constant.js";

// ==============================
// Logger
// ==============================
import logger from "../logger/logger.js";

// ==============================
// Database Connection
// ==============================
export const connect = async () => {
  try {
    await connectDB(mongoUrl, mongoDb);
  } catch (err) {
    logger.error("Failed to connect DB:", err);
    process.exit(1);
  }
};

// ==============================
// Before All
// ==============================
beforeAll(async () => {
  await connect();
}, 15000);
