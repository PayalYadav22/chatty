import "../config/env.config.js";

import mongoose from "mongoose";
import connectDB from "./config/db.config.js";
import { mongoUrl, mongoDb } from "./constants/constant.js";

import logger from "../logger/logger.js";

export const connect = async () => {
  try {
    await connectDB(mongoUrl, mongoDb);
  } catch (err) {
    logger.error("Failed to connect DB:", err);
    process.exit(1);
  }
};

beforeAll(async () => {
  await connect();
}, 15000);
