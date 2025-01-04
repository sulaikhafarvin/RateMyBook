import { Router } from "express";

import {
  renderSignup,
  createUser,
  verifyEmail,
  renderLogin,
  verifyUser,
  renderHome,
  userLogout,
  renderForget,
  forgetPassword,
  renderResetPassword,
  resetpassword,
  renderUserProfilePage,
  uploadProfilePicture,
  updateProfile,
  changePassword,
  renderBookPage,
  reviewBook,
  rateBook,
  renderUserReviewPage,
  createReview,
  deleteReview,
} from "../controller/userController.js";
import isUserLoggedIn from "../middleware/authMiddleware.js";

const userRoute = Router();

userRoute.get("/signup", renderSignup);
userRoute.get("/login", renderLogin);

userRoute.post("/signup", createUser);
userRoute.post("/login", verifyUser);
userRoute.post("/forget", forgetPassword);
userRoute.post("/reset-password", resetpassword);
userRoute.post("/profile/upload", isUserLoggedIn, uploadProfilePicture);
userRoute.post("/profile/update", isUserLoggedIn, updateProfile);
userRoute.post("/profile/change-password", isUserLoggedIn, changePassword);
userRoute.post("/review/:id", isUserLoggedIn, reviewBook);
userRoute.post("/rate/:id", isUserLoggedIn, rateBook);
userRoute.post("/reviews/:bookId", isUserLoggedIn, createReview);

userRoute.get("/verify", verifyEmail);
userRoute.get("/home", isUserLoggedIn, renderHome);
userRoute.get("/logout", userLogout);
userRoute.get("/forget", renderForget);
userRoute.get("/reset-password", renderResetPassword);
userRoute.get("/profile", isUserLoggedIn, renderUserProfilePage);
userRoute.get("/book/:id", isUserLoggedIn, renderBookPage);
userRoute.get("/reviews/:id", isUserLoggedIn, renderUserReviewPage);

userRoute.delete("/reviews/delete/:reviewId", isUserLoggedIn, deleteReview);

export default userRoute;
