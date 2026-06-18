import mongoose from "mongoose";
import config from "./config.js";

async function connectdb() {
  try {
    console.log("Attempting MongoDB connection...");

    const db = await mongoose.connect(config.MONGODB_URI);

    console.log("Database connected successfully");
    console.log("Host:", db.connection.host);
  } catch (error) {
    console.error("MongoDB Connection Failed:");
    console.error(error);
    process.exit(1);
  }
}

export default connectdb;