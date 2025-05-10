import express from "express";
import authRoute from "./auth/routes.js";
import usersRoute from "./users/routes.js";
import messageRoute from "./message/routes.js";

const router = express.Router();

router.use("/auth", authRoute);
router.use("/users", usersRoute);
router.use("/message", messageRoute);

export default router;
