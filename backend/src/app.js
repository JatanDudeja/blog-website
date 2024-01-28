import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser"; // to perform crud operations on cookies present on user's browser

const app = express();

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json({ limit: "16kb" })); // to accept json
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());

// routes declaration

import userRouter from "./routes/user.route.js";

app.use("/api/v1/users", userRouter);

export { app };
