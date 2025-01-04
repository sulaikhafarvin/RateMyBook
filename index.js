import connectToDatabase from "./config/db.js";
import express, { urlencoded } from "express";
import dotenv from "dotenv";
import userRoute from "./routes/userRoute.js";
import adminRoute from "./routes/adminRoute.js";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import methodOverride from "method-override";

dotenv.config();

const PORT = process.env.PORT;
const app = express();

app.use(express.json());
app.use(urlencoded({ extended: true }));
app.use(cookieParser());
app.use(methodOverride("_method"));

// Serve static files from the "public" directory
app.use(express.static("public"));

// Get current directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Serve static files from the "uploads" directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.set("view engine", "ejs");
// app.set("views", "./views");

// Route for the home page
app.get('/', (req, res) => {
  const page = req.query.page || 'home'; // Default to 'home' if no query parameter
  res.render('index', { page }); // Render index.ejs with 'home' content
});

app.use("/user", userRoute);
app.use("/admin", adminRoute);

connectToDatabase()
  .then(() => {
    console.log("Connected to Mongodb Atlas");
  })
  .catch((error) => {
    console.error("Database Connection Failed", error);
  });

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});
