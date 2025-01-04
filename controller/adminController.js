import User from "../models/userModel.js";
import Book from "../models/bookModel.js";
import Rate from "../models/rateModel.js";
import Review from "../models/reviewModel.js";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { upload } from "../middleware/upload.js";

dotenv.config();

const secret = process.env.SECRET;

export const renderLogin = async (req, res) => {
  try {
    res.render("admin/login");
  } catch (error) {
    console.log(error.message);
  }
};

export const verifyAdminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.render("admin/login", {
        message: "Email and Password are required",
      });
    }

    const user = await User.findOne({ email, is_admin: 1 });

    if (!user) {
      return res.render("admin/login", {
        message: "Email and Password is incorrect",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.render("admin/login", {
        message: "Email and Password is incorrect",
      });
    }

    if (user.is_admin === 0) {
      return res.render("admin/login", {
        message: "Access denied. Not an admin.",
      });
    }

    const token = jwt.sign({ id: user._id }, secret, { expiresIn: "1h" });

    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });

    return res.redirect("/admin/home");
  } catch (error) {
    console.error("Error in verify Admin Login:", error.message);
    res.status(500).render("500", { message: "Internal Server Error" });
  }
};

export const renderDashboard = async (req, res) => {
  try {
    const token = req.cookies.auth_token;

    if (!token) {
      return res.redirect("admin/login");
    }

    const decoded = jwt.verify(token, secret);

    const user = await User.findById(decoded.id);
    // console.log(user);

    if (!user) {
      return res.status(404).render("404", { message: "User not found" });
    }

    // Fetch user and book counts
    const userCount = await User.countDocuments({ is_admin: 0 });
    const bookCount = await Book.countDocuments();

    // Render the admin dashboard with counts
    res.render("admin/home", { user, userCount, bookCount });
  } catch (error) {
    console.error("Error in renderDashboard:", error.message);
    res.status(500).render("500", { message: "Internal Server Error" });
  }
};

export const adminLogout = async (req, res) => {
  try {
    res.clearCookie("auth_token", { httpOnly: true, secure: true });

    res.redirect("/admin/login");
  } catch (error) {
    console.error("Logout error:", error.message);
    res.status(500).json({ error: "Error in logging out" });
  }
};

// USer

export const renderUserPage = async (req, res) => {
  try {
    const users = await User.find({ is_admin: { $ne: 1 } }); // Exclude admin users
    res.render("admin/users", { users });
  } catch (error) {
    console.log(error.message);
  }
};

export const banUser = async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { is_active: false });
    res.redirect("/admin/users");
  } catch (error) {
    console.error("Error banning user:", error.message);
    res.status(500).send("Error banning user");
  }
};

export const activateUser = async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { is_active: true });
    res.redirect("/admin/users");
  } catch (error) {
    console.error("Error activating user:", error.message);
    res.status(500).send("Error activating user");
  }
};

// Books

export const renderBooksPage = async (req, res) => {
  try {
    const books = await Book.find(); // Fetch all books from the database
    res.render("admin/books", { books });
  } catch (error) {
    console.error("Error fetching books:", error);
    res.status(500).render("500", { message: "Internal Server Error" });
  }
};

export const renderCreateBookPage = async (req, res) => {
  try {
    res.render("admin/create-book", { message: null });
  } catch (error) {
    console.log(error.message);
  }
};

// Create a new book
export const createBook = async (req, res) => {
  try {
    // Run Multer to upload the file
    upload(req, res, async (err) => {
      if (err) {
        return res.status(400).render("admin/create-book", {
          message: err.message,
        });
      }

      const { title, author, genre, description, buyLink } = req.body;
      const coverImage = req.file ? req.file.path : ""; // Store the file path

      if (!title || !author || !genre || !description) {
        return res.status(400).render("admin/create-book", {
          message: "All fields are required",
        });
      }

      const newBook = new Book({
        title,
        author,
        genre,
        description,
        coverImage,
        buyLink,
      });

      await newBook.save();
      res.redirect("/admin/books");
    });
  } catch (error) {
    console.error("Error creating book:", error.message);
    res.status(500).render("500", { message: "Internal Server Error" });
  }
};

export const renderBook = async (req, res) => {
  try {
    const bookId = req.params.id; // Ensure the route passes the book ID
    const book = await Book.findById(bookId);

    if (!book) {
      return res.status(404).render("404", { message: "Book not found" });
    }

    // Fetch related ratings and reviews
    const ratings = await Rate.find({ bookId });
    const reviews = await Review.find({ bookId }).populate(
      "userId",
      "username"
    );

    res.render("admin/book", {
      book: {
        ...book.toObject(),
        ratings: ratings.map((rate) => rate.score),
        reviews: reviews.map((review) => ({
          username: review.userId.username,
          reviewText: review.text,
          rating: review.rating,
        })),
      },
    });
  } catch (error) {
    console.error("Error fetching book details:", error);
    res.status(500).render("500", { message: "Internal Server Error" });
  }
};

// Edit Book
export const renderEditBookPage = async (req, res) => {
  try {
    const bookId = req.params.id;
    const book = await Book.findById(bookId);

    if (!book) {
      return res.status(404).send("Book not found");
    }

    res.render("admin/edit", { book });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal Server Error");
  }
};

// Update Book function
export const updateBook = async (req, res) => {
  try {
    // Run Multer to upload the file
    upload(req, res, async (err) => {
      if (err) {
        return res.status(400).render("admin/edit", {
          message: err.message,
          book: req.body, // Retain form data if upload fails
        });
      }

      const bookId = req.params.id;
      const { title, author, genre, description, buyLink } = req.body;

      // If a new cover image is uploaded, set the path
      const coverImage = req.file ? "/uploads/" + req.file.filename : undefined;

      // Find and update the book
      const updatedData = { title, author, genre, description, buyLink };
      if (coverImage) {
        updatedData.coverImage = coverImage; // Update the cover image if a new one is uploaded
      }

      // Find the book by ID and update it
      const book = await Book.findByIdAndUpdate(bookId, updatedData, {
        new: true, // Return the updated book
        runValidators: true, // Run validations
      });

      if (!book) {
        return res.status(404).render("404", { message: "Book not found" });
      }

      // Redirect to the updated book page
      res.redirect(`/admin/books/${book._id}`);
    });
  } catch (error) {
    console.error("Error updating book:", error.message);
    res.status(500).render("500", { message: "Internal Server Error" });
  }
};
