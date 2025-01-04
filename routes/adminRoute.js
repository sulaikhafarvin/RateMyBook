import { Router } from "express";
import {
  renderLogin,
  verifyAdminLogin,
  renderDashboard,
  adminLogout,
  renderUserPage,
  banUser,
  activateUser,
  renderBooksPage,
  createBook,
  renderCreateBookPage,
  renderBook,
  renderEditBookPage,
  updateBook,
} from "../controller/adminController.js";
import isAdminLoggedIn from "../middleware/adminAuthMiddleware.js";

const adminRoute = Router();

// adminRoute.use((req, res, next) => {
//   req.app.set("views", "./views/admin");
//   next();
// });

adminRoute.get("/login", renderLogin);
adminRoute.get("/home", isAdminLoggedIn, renderDashboard);
adminRoute.get("/logout", adminLogout);
adminRoute.get("/users", isAdminLoggedIn, renderUserPage);
adminRoute.get("/books", isAdminLoggedIn, renderBooksPage);
adminRoute.get("/books/create", isAdminLoggedIn, renderCreateBookPage);
adminRoute.get("/books/:id", isAdminLoggedIn, renderBook);
adminRoute.get("/books/:id/edit", isAdminLoggedIn, renderEditBookPage);

adminRoute.post("/login", verifyAdminLogin);
adminRoute.post("/ban-user/:id", isAdminLoggedIn, banUser);
adminRoute.post("/activate-user/:id", isAdminLoggedIn, activateUser);
adminRoute.post("/books/create", isAdminLoggedIn, createBook);

adminRoute.put("/books/:id", isAdminLoggedIn, updateBook);
export default adminRoute;
