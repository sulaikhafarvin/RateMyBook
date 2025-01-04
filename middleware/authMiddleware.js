import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

const secret = process.env.SECRET;
const isUserLoggedIn = (req, res, next) => {
  try {
    // Ensure cookies exist
    if (!req.cookies || !req.cookies.auth_token) {
      return res.redirect("/user/login"); // Redirect if no token found
    }

    const token = req.cookies.auth_token;

    // Verify token
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        console.error("Token verification error:", err);
        return res.status(401).json({ error: "Unauthorized access" });
      }
      req.user = decoded; // Attach decoded user info to request
      next(); // Proceed to next middleware/route
    });
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ error: "Server error during authentication" });
  }
};

export default isUserLoggedIn;
