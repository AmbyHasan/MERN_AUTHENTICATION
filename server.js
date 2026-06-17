//the purpose of this file is to start the server and to connect with the db


import app from "./src/app.js";
import connectdb from "./config/db.js";

connectdb();

app.listen(3000 , ()=>{
    console.log("Server is running on port 3000");
});
