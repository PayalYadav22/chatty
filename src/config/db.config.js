import mongoose from "mongoose";

mongoose.set("strictQuery", true);

const connectDB = async (url, db) => {
  try {
    await mongoose.connect(`${url}/${db}`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  } catch (error) {
    console.log("Database Connection Failed");
  }
};

export default connectDB;
