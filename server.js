require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

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

    resetCodeHash: { type: String, default: null },
    resetCodeExp: { type: Date, default: null },
  },
  { timestamps: true, collection: "users" }
);

const User = mongoose.model("User", userSchema, "users");

// ✅ JWT Auth Middleware
const auth = (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

    if (!token) return res.status(401).json({ message: "Missing token" });

    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_secret");
    req.userId = payload.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ✅ Auth: Register / Login
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

// ✅ Profile: GET/PUT /api/users/me
app.get("/api/users/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("_id name email");
    if (!user) return res.status(404).json({ message: "User not found" });

    return res.json({
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: String(err) });
  }
});

app.put("/api/users/me", auth, async (req, res) => {
  try {
    const { name, email } = req.body;

    const n = String(name || "").trim();
    const em = String(email || "").trim().toLowerCase();

    if (n.length < 2)
      return res.status(400).json({ message: "Name must be at least 2 characters" });

    if (!emailRegex.test(em))
      return res.status(400).json({ message: "Invalid email" });

    const exists = await User.findOne({ email: em, _id: { $ne: req.userId } });
    if (exists) return res.status(409).json({ message: "Email already exists" });

    const updated = await User.findByIdAndUpdate(
      req.userId,
      { name: n, email: em },
      { new: true, runValidators: true }
    ).select("_id name email");

    if (!updated) return res.status(404).json({ message: "User not found" });

    return res.json({
      message: "Profile updated ✅",
      user: { id: updated._id, name: updated.name, email: updated.email },
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: String(err) });
  }
});

// ✅ Forgot Password: POST /api/auth/forgot-password
const buildMailer = () => {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
};

const mailer = buildMailer();

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();

    if (!emailRegex.test(email))
      return res.status(400).json({ message: "Invalid email" });

    const user = await User.findOne({ email });

    if (!user) return res.json({ ok: true, exists: false });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const hash = await bcrypt.hash(code, 10);
    const exp = new Date(Date.now() + 10 * 60 * 1000);

    user.resetCodeHash = hash;
    user.resetCodeExp = exp;
    await user.save();

    if (mailer) {
      const from = process.env.SMTP_FROM || process.env.SMTP_USER;
      await mailer.sendMail({
        from,
        to: email,
        subject: "Wassl - Reset Password Code",
        text: `رمز إعادة تعيين كلمة المرور هو: ${code}\nينتهي خلال 10 دقائق.`,
      });
      return res.json({ ok: true, exists: true, message: "Code sent ✅" });
    }

    return res.json({
      ok: true,
      exists: true,
      message: "Dev mode: SMTP not configured",
      code,
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: String(err) });
  }
});

// ✅ Reset Password: POST /api/auth/reset-password
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (!emailRegex.test(email))
      return res.status(400).json({ message: "Invalid email" });

    if (!code || code.length < 4)
      return res.status(400).json({ message: "Invalid code" });

    if (newPassword.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "Email not found" });

    if (!user.resetCodeHash || !user.resetCodeExp)
      return res.status(400).json({ message: "No reset request found" });

    if (new Date() > new Date(user.resetCodeExp))
      return res.status(400).json({ message: "Code expired" });

    const ok = await bcrypt.compare(code, user.resetCodeHash);
    if (!ok) return res.status(400).json({ message: "Wrong code" });

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetCodeHash = null;
    user.resetCodeExp = null;
    await user.save();

    return res.json({ ok: true, message: "Password updated ✅" });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: String(err) });
  }
});

const PORT = process.env.PORT || 5055;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Backend listening on http://0.0.0.0:${PORT}`);
});
