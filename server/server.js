const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");

const app = express();

// Middleware
app.use(cors({
  origin: 'http://localhost:3000', // React app URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Allows cookies/auth headers to be sent
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection setup
mongoose.connect("mongodb://localhost:27017/users", {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log("MongoDB Connected");
}).catch((err) => {
  console.error("Error connecting to MongoDB:", err);
});

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  password: String
});

const User = mongoose.model("User", userSchema);

// Register Route
app.post("/register", async (req, res) => {
  const { name, email, tel, password, confirmPass } = req.body;

  if (password !== confirmPass) {
    return res.status(400).send("Passwords do not match");
  }

  // Hash password before saving it
  const hashedPassword = bcrypt.hashSync(password, 10);

  try {
    const newUser = new User({ name, email, phone: tel, password: hashedPassword });
    await newUser.save();
    res.status(201).send("User registered...");
  } catch (err) {
    if (err.code === 11000) { // Duplicate email
      return res.status(400).send("User already exists");
    }
    console.error(err);
    return res.status(500).send("Error registering user");
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { email, pass } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("Invalid email or password");

    const isPasswordValid = bcrypt.compareSync(pass, user.password);
    if (!isPasswordValid) return res.status(400).send("Invalid email or password");

    const token = jwt.sign({ id: user._id }, "secretKey", { expiresIn: "1h" });
    res.send({ message: "Login successful", token });
  } catch (err) {
    res.status(500).send("Login error");
  }
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Bearer token
  if (!token) {
    return res.status(403).send("Access denied");
  }
  try {
    const verified = jwt.verify(token, "secretKey"); // Verify token with secret
    req.user = verified; // Set the user ID in the request
    next();
  } catch (error) {
    return res.status(401).send("Invalid token");
  }
};

// Profile Route
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id, 'name email phone');
    if (!user) return res.status(404).send("User not found");
    res.json(user); // Send the user details
  } catch (err) {
    res.status(500).send("Database error");
  }
});

// Send OTP to the user's email
let otpStorage = {}; // In-memory OTP storage, use Redis/DB for production

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'srinivaskatreedi369@gmail.com', // Your email
    pass: 'hypm wspq pwim jwdp', // Your app-specific password
  },
});

// Send OTP Route
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).send("User not found");

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    otpStorage[email] = otp;

    // Send email with OTP
    const mailOptions = {
      from: "srinivaskatreedi369@gmail.com",
      to: email,
      subject: "Your Password Reset OTP",
      text: `Your OTP for password reset is ${otp}`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).send("Error sending email");
      }
      res.send("OTP sent to your email");
    });
  } catch (err) {
    res.status(500).send("Error sending OTP");
  }
});

// Verify OTP Route
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  // Check if OTP matches the one sent to the user's email
  if (!otpStorage[email] || otpStorage[email] !== otp) {
    return res.status(400).send("Invalid OTP");
  }

  // If OTP matches, send success message
  res.send("OTP verified");
});

// Reset Password Route
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!otpStorage[email] || otpStorage[email] !== otp) {
    return res.status(400).send("Invalid OTP");
  }

  const hashedPassword = bcrypt.hashSync(newPassword, 10);

  try {
    await User.updateOne({ email }, { password: hashedPassword });
    delete otpStorage[email]; // Clear OTP after successful reset
    res.send("Password has been reset");
  } catch (err) {
    res.status(500).send("Error updating password");
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
