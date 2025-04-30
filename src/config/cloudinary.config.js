/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import { v2 as cloudinary } from "cloudinary";
import fs from "fs/promises";

import {
  cloudinaryName,
  cloudinaryApiKey,
  cloudinaryApiSecret,
} from "../constants/constant.js";

cloudinary.config({
  cloud_name: cloudinaryName,
  api_key: cloudinaryApiKey,
  api_secret: cloudinaryApiSecret,
});

const uploadFileToCloudinary = async (localFilePath) => {
  try {
    if (!localFilePath) return null;
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    fs.unlink(localFilePath);
    return response;
  } catch (error) {
    fs.unlink(localFilePath);
    console.error("Error uploading file to Cloudinary:", error);
    return null;
  }
};

const deleteFileToCloudinary = async (localFilePath) => {
  try {
    return await cloudinary.uploader.destroy(localFilePath);
  } catch (error) {
    console.error("Error deleting image:", error);
    throw error;
  }
};

export { uploadFileToCloudinary, deleteFileToCloudinary };
