import User from "../models/userModel.js";
import Book from "../models/bookModel.js";
import Review from "../models/reviewModel.js";
import Rate from "../models/rateModel.js";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import fs from "fs";
import { upload } from "../middleware/UploadPro.js";
import cloudinary from "cloudinary";

dotenv.config();

const secret = process.env.SECRET;

export const renderSignup = (req, res) => {
  res.render("signup");
};

// For Email Verification

const sendVerifyMail = async (username, email, user_id) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "For Verification Email",
      html:
        "<p> Hi " +
        username +
        ', Please click here to <a href="http://localhost:3011/user/verify?id=' +
        user_id +
        '">Verify</a> your email.</p>',
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        console.log("Email has been sent:", info.response);
      }
    });
  } catch (error) {
    console.log(error.message);
  }
};

export const createUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already taken" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      is_admin: 0,
    });

    if (user) {
      sendVerifyMail(req.body.username, req.body.email, user._id);
      res.render("signup", {
        message: "Please check your email to verify your account.",
      });
    } else {
      res.render("signup", { message: "Sign-in is Un-successful!" });
    }
  } catch (error) {
    console.error("Error creating user:", error);
    res
      .status(400)
      .json({ error: "Error in Creating User", details: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const updateInfo = await User.updateOne(
      { _id: req.query.id },
      { $set: { is_verified: 1 } }
    );
    console.log(updateInfo);

    res.render("email-verified");
  } catch (error) {
    console.log(error.message);
  }
};

export const renderLogin = async (req, res) => {
  try {
    res.render("login");
  } catch (error) {
    console.log(error.message);
  }
};

export const verifyUser = async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });

    if (user && (await bcrypt.compare(req.body.password, user.password))) {
      // Check if the user is verified
      if (user.is_verified === 0) {
        return res.render("login", { message: "Please verify your email" });
      }

      // Check if the user is active
      if (user.is_active === false) {
        return res.render("login", {
          message: "Your account is banned.",
        });
      }
      // Generate a token and set it as a cookie
      const token = jwt.sign({ id: user._id }, secret, {
        expiresIn: "1h",
      });

      res.cookie("auth_token", token, { httpOnly: true });
      return res.redirect("/user/home");
    } else {
      return res.render("login", {
        message: "Username and Password are incorrect",
      });
    }
  } catch (error) {
    console.error("Error in verifying User:", error);
    res
      .status(400)
      .json({ error: "Error in verifying User", details: error.message });
  }
};

export const userLogout = async (req, res) => {
  try {
    // Clear the auth token cookie
    res.clearCookie("auth_token", { httpOnly: true, secure: true });

    // Redirect the user to the home or login page
    res.redirect("/user/login");
  } catch (error) {
    console.error("Logout error:", error.message);
    res.status(500).json({ error: "Error in logging out" });
  }
};

// Forget Password

export const renderForget = async (req, res) => {
  try {
    res.render("forget");
  } catch (error) {
    console.log(error.message);
  }
};

export const forgetPassword = async (req, res) => {
  try {
    const email = req.body.email;
    const user = await User.findOne({ email: email });

    if (user) {
      // Check if the user's email is verified
      if (user.is_verified === 0) {
        return res.render("forget", { message: "Please verify your email." });
      }

      // Generate a password reset token
      const token = jwt.sign({ id: user._id }, secret, {
        expiresIn: "1h", // Token valid for 1 hour
      });

      // Set up Nodemailer
      const transporter = nodemailer.createTransport({
        service: "gmail", // Use Gmail service
        auth: {
          user: process.env.EMAIL_USER, // Your email
          pass: process.env.EMAIL_PASS, // Your email password or app password
        },
      });

      // Compose the reset email
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Reset Your Password",
        html: `
          <p>Hi ${user.username},</p>
          <p>You requested to reset your password. Please click the link below to reset it:</p>
          <a href="http://localhost:3011/user/reset-password?token=${token}" >Reset Password</a>
          <p>If you didn't request this, please ignore this email.</p>
        `,
      };

      // Send the email
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("Error sending email:", error);
          res.render("forget", {
            message: "Error sending reset email. Please try again later.",
          });
        } else {
          console.log("Email sent:", info.response);
          res.render("forget", {
            message:
              "Password reset email sent successfully. Please check your inbox.",
          });
        }
      });
    } else {
      res.render("forget", { message: "User email is incorrect." });
    }
  } catch (error) {
    console.log("Error in forgetPassword:", error.message);
    res.render("forget", {
      message: "An error occurred. Please try again later.",
    });
  }
};

export const renderResetPassword = async (req, res) => {
  try {
    const token = req.query.token;

    // Verify the token
    jwt.verify(token, secret, async (err, decoded) => {
      if (err) {
        // Handle invalid or expired token error
        return res.render("404", { message: "Token is invalid or expired" });
      }

      // Token is valid, proceed to reset the password
      const user = await User.findById(decoded.id); // Use decoded.id to find the user

      if (!user) {
        return res.render("404", { message: "User not found" });
      }

      // If the user exists and token is valid, render the reset-password page
      res.render("reset-password", { user_id: user._id });
    });
  } catch (error) {
    console.log(error.message);
    res.render("404", {
      message: "An error occurred while processing your request.",
    });
  }
};

export const resetpassword = async (req, res) => {
  try {
    const { password, user_id } = req.body;

    // Validate input
    if (!password || !user_id) {
      return res.render("reset-password", {
        message: "Password and User ID are required.",
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the password directly in the database
    const user = await User.findByIdAndUpdate(
      user_id,
      { $set: { password: hashedPassword } },
      { new: true }
    );

    if (!user) {
      return res.render("reset-password", { message: "User not found." });
    }

    // Redirect to login page after successful password reset
    res.render("login", {
      message: "Password reset successfully. Please log in.",
    });
  } catch (error) {
    console.error("Error resetting password:", error.message);
    res.render("reset-password", {
      message: "An error occurred. Please try again later.",
    });
  }
};

// User profile

export const renderUserProfilePage = async (req, res) => {
  try {
    // Get the token from cookies
    const token = req.cookies.auth_token;

    if (!token) {
      return res.status(401).send("Unauthorized: No token provided");
    }

    // Verify and decode the token
    const decoded = jwt.verify(token, secret);
    const userId = decoded.id;

    // Fetch the user from the database
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).send("User not found");
    }

    // Fetch rated and reviewed books
    const ratedBooks = await Rate.find({ userId }).populate("bookId");
    const reviewedBooks = await Review.find({ userId: user._id }).populate(
      "bookId"
    );

    // Render the profile page
    res.render("profile", {
      user,
      ratedBooks: ratedBooks.map((rating) => ({
        title: rating.bookId.title,
        cover: rating.bookId.coverImage,
        rating: rating.score,
      })),
      reviewedBooks: reviewedBooks.map((review) => ({
        title: review.bookId.title,
        cover: review.bookId.coverImage,
        review: review.text,
      })),
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("An error occurred while rendering the profile page.");
  }
};

// upload profile pic

export const uploadProfilePicture = async (req, res) => {
  // Use Multer's upload middleware directly inside the function
  upload.single("profilePicture")(req, res, async (err) => {
    if (err) {
      console.error("Multer error:", err.message);
      return res.status(400).send("Error uploading file: " + err.message);
    }

    try {
      // Ensure a file was uploaded
      if (!req.file) {
        return res.status(400).send("No file uploaded");
      }

      // Extract the user from the token
      const token = req.cookies.auth_token;
      if (!token) return res.status(401).send("Unauthorized");

      const decoded = jwt.verify(token, secret);
      const userId = decoded.id;

      // Fetch user from database
      const user = await User.findById(userId);
      if (!user) return res.status(404).send("User not found");

      // Delete the old profile picture if it exists (Optional for Cloudinary)
      if (user.profilePicture) {
        const publicId = user.profilePicture.split("/").pop().split(".")[0]; // Extract public ID
        cloudinary.v2.uploader.destroy(publicId, (error, result) => {
          if (error)
            console.error("Failed to delete old profile picture:", error);
        });
      }

      // Save the new profile picture URL
      user.profilePicture = req.file.path; // Use the full URL from Cloudinary
      await user.save();

      res.redirect("/user/profile");
    } catch (error) {
      console.error("Error uploading profile picture:", error.message);
      res
        .status(500)
        .send("An error occurred while uploading the profile picture.");
    }
  });
};

// Update Profile
export const updateProfile = async (req, res) => {
  const { username, email } = req.body;
  const token = req.cookies.auth_token;

  if (!token) return res.status(401).send("Unauthorized");

  try {
    const decoded = jwt.verify(token, secret);
    const userId = decoded.id;
    const user = await User.findById(userId);

    if (!user) return res.status(404).send("User not found");

    user.username = username;
    user.email = email;
    await user.save();

    res.redirect("/user/profile");
  } catch (err) {
    res.status(500).send("Server Error");
  }
};

// Change Password
export const changePassword = async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const token = req.cookies.auth_token;

  if (!token) return res.status(401).send("Unauthorized");

  try {
    const decoded = jwt.verify(token, secret);
    const userId = decoded.id;
    const user = await User.findById(userId);

    if (!user) return res.status(404).send("User not found");

    // Check if current password matches
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).send("Current password is incorrect");

    // Check if new password matches confirm password
    if (newPassword !== confirmPassword)
      return res.status(400).send("Passwords do not match");

    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.redirect("/user/profile");
  } catch (err) {
    res.status(500).send("Server Error");
  }
};
// Home
export const renderHome = async (req, res) => {
  try {
    const token = req.cookies.auth_token;

    if (!token) {
      return res.redirect("/user/login");
    }

    const decoded = jwt.verify(token, secret);

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).render("404", { message: "User not found" });
    }

    // const books = await Book.find(); // Adjust this as per your database

    // Get search query from the request
    const searchQuery = req.query.search || "";

    // Find books based on the search query
    let books;
    if (searchQuery) {
      // Search books by title or author (you can customize this)
      books = await Book.find({
        $or: [
          { title: { $regex: searchQuery, $options: "i" } },
          { author: { $regex: searchQuery, $options: "i" } },
        ],
      });
    } else {
      books = await Book.find(); // Return all books if no search query
    }

    // Find the most rated book
    const mostRatedBook = await Rate.aggregate([
      {
        $group: {
          _id: "$bookId",
          averageRating: { $avg: "$score" },
          totalRatings: { $sum: 1 },
        },
      },
      { $sort: { totalRatings: -1 } }, // Sort by the number of ratings in descending order
      { $limit: 1 }, // Get the top book
      {
        $lookup: {
          from: "books",
          localField: "_id",
          foreignField: "_id",
          as: "book",
        },
      },
      { $unwind: "$book" },
    ]);

    // Find the most reviewed book
    const mostReviewedBook = await Review.aggregate([
      { $group: { _id: "$bookId", totalReviews: { $sum: 1 } } },
      { $sort: { totalReviews: -1 } }, // Sort by the number of reviews in descending order
      { $limit: 1 }, // Get the top book
      {
        $lookup: {
          from: "books",
          localField: "_id",
          foreignField: "_id",
          as: "book",
        },
      },
      { $unwind: "$book" },
    ]);

    res.render("home", {
      user,
      books,
      mostRatedBook: mostRatedBook.length > 0 ? mostRatedBook[0].book : null,
      mostReviewedBook:
        mostReviewedBook.length > 0 ? mostReviewedBook[0].book : null,
      searchQuery,
    });
  } catch (error) {
    console.error("Error in renderHome:", error.message);
    res.status(500).render("500", { message: "Internal Server Error" });
  }
};

// Book

export const renderBookPage = async (req, res) => {
  try {
    const userId = req.user.id; // Assuming user is authenticated

    // Fetch the book details
    const book = await Book.findById(req.params.id);

    // Fetch reviews and populate the userId for displaying usernames
    const reviews = await Review.find({ bookId: req.params.id }).populate(
      "userId"
    );

    // Fetch all ratings and calculate the average rating
    const ratings = await Rate.find({ bookId: req.params.id }).populate(
      "userId"
    );

    const averageRating =
      ratings.length > 0
        ? (
            ratings.reduce((sum, rate) => sum + rate.score, 0) / ratings.length
          ).toFixed(1)
        : 0;

    // Calculate the average rating percentage
    const averageRatingPercentage = Math.round((averageRating / 5) * 100);

    // Fetch the current user's rating for this book
    const userRating = await Rate.findOne({ bookId: req.params.id, userId });

    // Render the book details page with reviews, ratings, averageRating, and userRating
    res.render("book", {
      book,
      reviews,
      ratings,
      averageRatingPercentage,
      userRating, // Pass the user's rating
    });
  } catch (error) {
    console.error("Error rendering book page:", error);
    res.status(500).send("Internal Server Error");
  }
};

// Review

export const reviewBook = async (req, res) => {
  try {
    await Review.create({
      userId: req.user.id,
      bookId: req.params.id,
      text: req.body.text,
    });
    res.redirect(`/user/book/${req.params.id}`);
  } catch (error) {
    console.log(error.message);
  }
};

// Rate

export const rateBook = async (req, res) => {
  const { score } = req.body;
  console.log(score);

  const bookId = req.params.id; // Book ID from the route
  console.log(bookId);

  const userId = req.user.id; // Assuming user is authenticated
  console.log(userId);

  try {
    // Check if user has already rated this book
    const existingUser = await Rate.findOne({ userId: userId, bookId: bookId });

    if (existingUser) {
      const existingRate = await Rate.findOne({ score: score });

      if (existingRate) {
        return res.status(400).json({
          message: "You have already rated this book.",
        });
      }
    } else {
      console.log("Ready to rate!");
    }

    await Rate.create({
      userId: req.user.id,
      bookId: req.params.id,
      score: req.body.score,
    });

    res.redirect(`/user/book/${req.params.id}`);
    console.log("Your rating has been submitted successfully.");
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "An error occurred while submitting your rating.",
    });
  }
};

// User Review Page
export const renderUserReviewPage = async (req, res) => {
  try {
    const bookId = req.params.id; // Extract the book ID from the route
    const reviews = await Review.find({ bookId }).populate("userId"); // Fetch reviews for the book and populate user details
    const book = await Book.findById(bookId); // Fetch book details

    if (!book) {
      return res.status(404).send("Book not found");
    }

    const loggedInUser = req.user; // Ensure user info is available from session/auth middleware
    if (!loggedInUser) {
      throw new Error("User not authenticated.");
    }

    // Check if the logged-in user has already reviewed the book
    const userHasReviewed = reviews.some(
      (review) =>
        review.userId && review.userId._id.toString() === loggedInUser.id
    );

    res.render("userReview", {
      reviews, // Pass reviews to the template
      book, // Pass book details
      userHasReviewed, // Pass the review flag
      user: loggedInUser, // Pass logged-in user info
    });
  } catch (error) {
    console.error("Error rendering user review page:", error.message);
    res.status(500).send("Internal Server Error");
  }
};

export const createReview = async (req, res) => {
  try {
    // Get the bookId from the URL parameter
    const { bookId } = req.params;

    // Check if the book exists
    const book = await Book.findById(bookId);
    if (!book) {
      return res.status(404).send("Book not found");
    }

    // Create a new review
    const newReview = new Review({
      text: req.body.text, // Review text from the form
      userId: req.user.id, // Assuming user is authenticated and `req.user` is available
      bookId: book._id, // Associate review with the book
    });

    // Save the review to the database
    await newReview.save();

    // Redirect or respond after saving the review
    res.redirect(`/user/reviews/${bookId}`); // Assuming you have a book detail page to view the review
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
};

export const deleteReview = async (req, res) => {
  try {
    const { reviewId } = req.params;

    // Find the review by its ID and delete it
    const review = await Review.findByIdAndDelete(reviewId);

    if (!review) {
      return res
        .status(404)
        .json({ success: false, message: "Review not found" });
    }
    const bookId = review.bookId;
    res.redirect(`/user/reviews/${bookId}`);
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};
