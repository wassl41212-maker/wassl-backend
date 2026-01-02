require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors({ origin: "*" }));
app.options(/.*/, cors());

app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("X-WASSL-BACKEND", "1");
  console.log("REQ:", req.method, req.url);
  next();
});

app.get("/", (req, res) => {
  res.json({ ok: true, message: "Wassl API is running ✅" });
});

app.get("/ping", (req, res) => {
  res.json({ ok: true, message: "pong ✅" });
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [emailRegex, "Invalid email"],
    },
    password: { type: String, required: true, minlength: 6 },
  },
  { timestamps: true, collection: "users" }
);

const User = mongoose.model("User", userSchema, "users");

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name) return res.status(400).json({ message: "name is required" });
    if (!email || !password)
      return res.status(400).json({ message: "email and password are required" });

    if (!emailRegex.test(String(email).trim()))
      return res.status(400).json({ message: "Invalid email" });

    if (String(password).length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const cleanEmail = String(email).toLowerCase().trim();

    const exists = await User.findOne({ email: cleanEmail });
    if (exists) return res.status(409).json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(String(password), 10);

    const user = await User.create({
      name: String(name).trim(),
      email: cleanEmail,
      password: hashed,
    });

    return res.status(201).json({
      message: "Account created ✅",
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: String(err) });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "email and password are required" });

    const cleanEmail = String(email).toLowerCase().trim();
    const user = await User.findOne({ email: cleanEmail });
    if (!user) return res.status(401).json({ message: "Invalid email or password" });

    const ok = await bcrypt.compare(String(password), user.password);
    if (!ok) return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || "dev_secret",
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Logged in ✅",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: String(err) });
  }
});

const PORT = process.env.PORT || 5055;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Backend listening on http://0.0.0.0:${PORT}`);
});

