import mongoose from "mongoose";

const otpSchema= new mongoose.Schema({
    email:{
        type:String , 
        required: [ true , "Email is required"]
    } ,
    user:{
        type:mongoose.Schema.ObjectId,
        ref : "users" ,
        required: [true , "user is required"]
    },
    otpHash:{
        type:String , 
        required: [true ,  "OTP hash is required"] 
    } ,
    expiresAt: {
        type:Date ,
        required: [true , "Expiration time is required"]
    }
} , {
    timestamps:true
})

const otpModel= mongoose.model("otps" , otpSchema);
export default otpModel