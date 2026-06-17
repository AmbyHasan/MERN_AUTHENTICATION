import { Router } from "express";
import  * as authController from "../controllers/auth.controllers.js"


const authRouter=Router();



authRouter.post("/register", authController.register);
authRouter.get("/get-me" , authController.getMe);
authRouter.get("/refresh-token" , authController.refreshToken);
authRouter.get("/logout" , authController.logout);

export default authRouter;