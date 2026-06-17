import mongoose from "mongoose";
import config from "./config.js";

async function  connectdb(){
    const db = await mongoose.connect(config.MONGODB_URI);
    console.log("Database connected successfully");
}

export default connectdb;
