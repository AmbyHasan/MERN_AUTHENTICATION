import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../../config/config.js";
import userModel from "../../models/user.model.js";
import cookieParser from "cookie-parser";
import sessionModel from "../../models/session.model.js";



export async function register(req ,res){

    //get info from the user
    const {username ,email , password}= req.body;

    if (!username || !email || !password) {
        return res.status(400).json({
            message: "All fields are required"
        });
    }

    //before creating the user in the db we will check whether it already exists or not
    const isAlreadyRegistered = await userModel.findOne({

        $or:[

            { username } ,
            { email }
        ]
    })

    if(isAlreadyRegistered){
        return res.status(409).json({
            message : "Username or email already exists"
        })
    }

    //now we will hash the password
       const  hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({
        username ,
        email ,
        password:hashedPassword
    });

    //now the user has been registered and we will create accesstoken and refreshtoken

    const refreshToken = jwt.sign({
        id : user._id ,
    }, config.JWT_SECRET ,
    {
        expiresIn:"6d"
    })  //it will be stored in cookies

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    res.cookie("refreshToken" , refreshToken,{
        httpOnly:true ,   //client side pe jo JS run hogi wo kabhi bhi cookies ke andar ke data ko access nhi kr payegi
        secure: process.env.NODE_ENV === "production",
        sameSite:"strict" ,
        maxAge: 6*24*60*60*1000 // 6 days
    });

    const session = await sessionModel.create({

        userId: user._id ,
        refreshTokenHash ,
        ip: req.ip ,
        userAgent: req.headers["user-agent"]

    })

    const accessToken = jwt.sign({
        id : user._id ,
        session: session._id ,
    }, config.JWT_SECRET ,
    {
        expiresIn:"15m"
    }) //it will be stored in memory

    res.status(201).json({
        message: "User registered successfully" ,
        user:{
            username:user.username ,
            email:user.email
        } ,
        accessToken
    })

}


export async function login(req , res){
    const {email , password}= req.body;

    const user = await userModel.findOne({email});
    if(!user){
        return res.status(401).json({
            message : "Invalid email or password"
        })
    }

    const  hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
    const isPasswordValid = hashedPassword == user.password; //checking if the password entered but the user is correct or not


    if(!isPasswordValid){
        return res.status(401).json({
            message : "Invalid password"
        })
    }
 

    //generate the refresh token
      const refreshToken = jwt.sign({
        id : user._id ,
    }, config.JWT_SECRET ,
    {
        expiresIn:"6d"
    })  //it will be stored in cookies

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    res.cookie("refreshToken" , refreshToken,{
        httpOnly:true ,   //client side pe jo JS run hogi wo kabhi bhi cookies ke andar ke data ko access nhi kr payegi
        secure: process.env.NODE_ENV === "production",
        sameSite:"strict" ,
        maxAge: 6*24*60*60*1000 // 6 days
    });

    const session = await sessionModel.create({

        userId: user._id ,
        refreshTokenHash ,
        ip: req.ip ,
        userAgent: req.headers["user-agent"]

    })

    const accessToken = jwt.sign({
        id : user._id ,
        session: session._id ,
    }, config.JWT_SECRET ,
    {
        expiresIn:"15m"
    }) //it will be stored in memory

    res.status(200).json({
        message : "User logged in successfully" ,
        user : {
            username : user.username , 
            email :  user.email
        } ,
        accessToken
    })

}

export async function getMe(req , res){

    //first of all we have to find out that the request is coming from which user
    //for that we will check the header

    const token = req.headers.authorization?.split(" ")[1];   //"Bearer token"

    if(!token){
        return res.status(401).json({
            message : "Token is missing"
        })
    }

    const decoded = jwt.verify(token , config.JWT_SECRET); //decoding the token

    //we will extract the user id from the decoded token

    const user = await userModel.findById(decoded.id);

    if(!user){
        return res.status(404).json({
            message:"User not found"
        });
    }

    res.status(200).json({
        message: "User fetched succeddfully" ,
        user:{
            username: user.username,
            email:user.email
        }
    })

    //now we have a problem if any one gets the access of some other user's token , then he can steal the data of that user
    //this is a major problem and we need to do something in order to prevent this thing from happening
    //now we have to think where to store our token so that this problem doesn't arrives with us

    // 1-> if we store our token in the localStorage that it can be stolen very easily as localStorage can be read by JS
    //2-> cookies are vulnerable to CSRF attacks if not configured properly.

    //therefore we store token in "memory", but whenever page reloads memory get cleared
    //therefore we use two tokens -> accesstoken and refershtoken

    //with the help of accesstoken server identifies the user
    //whever the page realods memory gets cleared so token gets lost
    //there is an api as /api/auth/refresh , the user hits the api with the refresh token and the api gives him new accesss token
    //the refresh token is stored in "cookies"
    //since refresh token in cookies because they are more sensitive than access tokens, they are usually stored in HttpOnly Secure cookies so that JavaScript cannot access them, reducing the risk of theft through XSS attacks

}


//function for generating new access token
export async function refreshToken(req ,res){

    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({
            message : "Refresh token not found"
        });
    }

    const decoded = jwt.verify(refreshToken , config.JWT_SECRET );

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    //we will check ki kahi aisa koi session to nhi hai jaha revoke false ho by using the hashed refresh token

    const session = await sessionModel.findOne({
        refreshTokenHash ,
        revoke:false
    });

    if(!session){

        //session already logout hochuka hai
        //is case me hm refresh token generate nhi karege

        return res.status(401).json({
            message : "Invalid refresh token"
        })

    }

    const accessToken = jwt.sign({
        id:decoded.id,
        session: session._id
    } , config.JWT_SECRET ,
    {
        expiresIn : "15m"
    });

    //just for adding an extra layer of security whenever we renew access token, we generate new refresh token as well

    const newRefreshToken = jwt.sign({
        id:decoded.id
    } , config.JWT_SECRET ,
    {
        expiresIn : "6d"
    })

    //since new refresh token is being generated ,so we will check if the session exists then update the refreshTokenHash

    const newRefreshTokenHash = crypto
        .createHash("sha256")
        .update(newRefreshToken)
        .digest("hex");

    session.refreshTokenHash = newRefreshTokenHash;

    await session.save();

    res.cookie("refreshToken" , newRefreshToken,{
        httpOnly:true ,   //client side pe jo JS run hogi wo kabhi bhi cookies ke andar ke data ko access nhi kr payegi
        secure: process.env.NODE_ENV === "production",
        sameSite:"strict" ,
        maxAge: 6*24*60*60*1000 // 6 days
    });

    res.status(200).json({
        message : "Access token refershed successfully" ,
        accessToken
    })

}

//function for logging out from a single device
export async function logout(req ,res){

    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(400).json({
            message: "Refresh token not found"
        })
    }

    const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash ,
        revoke:false
    });

    if(!session){
        return res.status(400).json({
            message : "Invalid refresh token"
        });
    }

    session.revoke = true;

    await session.save();

    //once the session gets reovked then we will block the user from generating nwe access token through refresh token

    res.clearCookie("refreshToken");

    res.status(200).json({
        message: "User logged out successfully"
    });

}

//function for logging out from all devices
export async function logoutAll(req  ,res){
 
    const refreshToken=req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(400).json({
            message: "Refresh token not found"
        })
    }

    const decoded= jwt.verify(refreshToken , config.JWT_SECRET);

    //user ke sare sesssions dhoondho and revoke ko false mark krdo
    await sessionModel.updateMany({
         userId:decoded.id , 
         revoke:false ,
         } ,
         {
            revoke :true 
        })

    res.clearCookie("refreshToken");
    res.status(200).json({
        message : "Logout from all devices successfully"
    })
    } 

