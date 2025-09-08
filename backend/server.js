import express from "express";
import dotenv from "dotenv";
import authrouter from "./routes/auth.route.js";
import connectDB from "./lib/db.lib.js";
import cookieParser from "cookie-parser";

dotenv.config();
const PORT = process.env.PORT || 5000;
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use("/auth", authrouter);

app.listen(5000, () => {
  console.log("Server is running on port: ", PORT);
  connectDB();
});
