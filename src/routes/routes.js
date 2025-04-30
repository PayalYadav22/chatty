import express from "express";
import authRoute from "./auth/routes.js";
import usersRoute from "./users/routes.js";

const router = express.Router();

router.use("/auth", authRoute);
router.use("/users", usersRoute);

export default router;
