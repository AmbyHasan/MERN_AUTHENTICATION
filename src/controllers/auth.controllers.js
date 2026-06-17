import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "../../config/config.js";
import userModel from "../../models/user.model.js";
import cookieParser from "cookie-parser";

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
      return   res.status(409).json({
            message : "Username or email already exists"
        })
    }

  
    //now we will hash the password 
  const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = await userModel.create({
        username ,
        email ,
        password:hashedPassword
    });

    //now the user has been registered and we will create accesstoken and refreshtoken

    const accessToken = jwt.sign({
        id : user._id ,
     }, config.JWT_SECRET ,
    {
        expiresIn:"15m"
    }) //it will be stored in memory

    const refreshToken = jwt.sign({
          id : user._id ,
     }, config.JWT_SECRET ,
    {
        expiresIn:"6d"
    })  //it will be stored in cookies


    res.cookie("refreshToken" , refreshToken,{
        httpOnly:true ,   //client side pe jo JS run hogi wo kabhi bhi cookies ke andar ke data ko access nhi kr payegi
        secure:true ,
        sameSite:"strict" ,
        maxAge: 6*24*60*60*1000 // 6 days
    });

    res.status(201).json({
        message: "User registered successfully" ,
        user:{
            username:user.username ,
            email:user.email
        } ,
        accessToken
    })



 

}



export async function getMe(req , res){
   //first of all we have to find out that the request is coming from which user
   //for that we will check the header

   const token = req.headers.authorization?.split(" ")[1];   //"Bearer token"
   if(!token){
    return res.status(401).json({message : "Token is missing"})
   }

   const decoded = jwt.verify(token , config.JWT_SECRET); //decoding the token
   //we will extract the user id from the decoded token
 
    const user = await userModel.findById(decoded.id);

    res.status(200).json({
        message: "User fetched succeddfully" ,
        user:{
            username: user.username,
            email:user.email        } 
        
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
        return res.status(401).json({message : "Refresh token not found"});
    }

    const decoded= jwt.verify(refreshToken , config.JWT_SECRET );

    const accessToken= jwt.sign({
        id:decoded.id
      } , config.JWT_SECRET , 
    { 
        expiresIn : "15m"
    });

    //just for adding an extra layer of security whenever we renew access token, we generate new refresh token as well

    const newRefreshToken= jwt.sign({
         id:decoded.id
      } , config.JWT_SECRET , 
    { 
        expiresIn : "6d"
    })


      res.cookie("refreshToken" , newRefreshToken,{
        httpOnly:true ,   //client side pe jo JS run hogi wo kabhi bhi cookies ke andar ke data ko access nhi kr payegi
        secure:true ,
        sameSite:"strict" ,
        maxAge: 6*24*60*60*1000 // 6 days
    });



    res.status(200).json({
        message : "Access token refershed successfully" , 
        accessToken
    })


}

