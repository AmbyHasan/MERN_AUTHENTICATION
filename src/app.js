import express from "express";
import morgan from "morgan"  //it is basically a logger ,which tells apke server par kab konsi request ayi thi ,what was the endpoint ,what was the method etc
import authRouter from "./routes/auth.routes.js";
import cookieParser from "cookie-parser";

const app=express();


app.use(express.json());
app.use(morgan("dev"));
app.use(cookieParser());


//routes

app.use("/api/auth" , authRouter);  //here /api/auth is the prefix


export default app;