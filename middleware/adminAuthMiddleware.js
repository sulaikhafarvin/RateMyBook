import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

const secret = process.env.SECRET;
const isAdminLoggedIn = (req, res, next) => {
  try {
    if (!req.cookies || !req.cookies.auth_token) {
      return res.redirect("/admin/login");
    }

    const token = req.cookies.auth_token;

    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        console.error("Token verification error:", err);
        return res.status(401).json({ error: "Unauthorized access" });
      }
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ error: "Server error during authentication" });
  }
};

export default isAdminLoggedIn;
