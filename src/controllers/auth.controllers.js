import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "../../config/config.js";
import userModel from "../../models/user.model.js";

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

    //now the user has been registered and we will create a token
    const token = jwt.sign({
        id : user._id ,
     }, config.JWT_SECRET ,
    {
        expiresIn:"1d"
    })

    res.status(201).json({
        message: "User registered successfully" ,
        user:{
            username:user.username ,
            email:user.email
        } ,
        token
    })



 

}



export async function getMe(req , res){
   //first of all we have to find out that the request is coming from which user
   //for that we will check the header

   const token = req.headers.authorization?.split(" ")[1];   //"Bearer token"
   if(!token){
    return res.statu(401).json({message : "Token is missing"})
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



}

