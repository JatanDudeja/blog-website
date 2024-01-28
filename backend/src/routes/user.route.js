import { Router } from "express";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import { changeCurrentPassword, getCurrectUser, loginUser, logoutUser, registerUser, updateAccount } from "../controllers/user.controller.js";



const router = Router();

router.route("/register").post(registerUser)

router.route("/login").post(loginUser)
router.route("/logout").post(verifyJWT, logoutUser)

router.route("/changePassword").post(verifyJWT, changeCurrentPassword)
router.route("/getCurrentUser").get(verifyJWT, getCurrectUser)
router.route("/updateUserDetails").post(verifyJWT, updateAccount)


export default router;