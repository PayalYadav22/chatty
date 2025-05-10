import mongoose from "mongoose";

const connectDB = async (url, db) => {
  try {
    await mongoose.connect(`${url}/${db}`);
  } catch (error) {
    console.log("Database Connection Failed");
  }
};

export default connectDB;
