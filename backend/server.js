const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET || "";
if (!JWT_SECRET || JWT_SECRET.length < 24) {
  console.warn("WARNING: JWT_SECRET is missing or too short. Set a long random value in backend/.env");
}

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const usersFilePath = path.join(__dirname, "user.json");

// --- Helpers: file storage (atomic writes) ---
async function ensureUsersFile() {
  try {
    await fs.access(usersFilePath);
  } catch {
    await fs.writeFile(usersFilePath, "[]", "utf8");
  }
}

async function readUsers() {
  await ensureUsersFile();
  const raw = await fs.readFile(usersFilePath, "utf8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeUsers(users) {
  const tmpPath = usersFilePath + ".tmp";
  await fs.writeFile(tmpPath, JSON.stringify(users, null, 2), "utf8");
  await fs.rename(tmpPath, usersFilePath);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongEnoughPassword(pw) {
  // Mock-production minimum: 8+ chars (keep it simple but not reckless)
  return typeof pw === "string" && pw.length >= 8;
}

// --- Security / middleware ---
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "50kb" }));
app.use(morgan("dev"));

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 60, // 60 req/min per IP
    standardHeaders: true,
    legacyHeaders: false
  })
);

// CORS: strict allowlist + proper preflight support
app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) {
        return cb(new Error("CORS blocked: missing Origin. Serve frontend via http:// (not file://)."));
      }
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked: Origin not allowed: ${origin}`));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 86400
  })
);

app.options("*", cors());

// --- Routes ---
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "API healthy",
    allowedOrigins
  });
});

app.post("/api/auth/signup", async (req, res, next) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!name || name.length < 2) {
      return res.status(400).json({ ok: false, error: "Name is required (min 2 characters)." });
    }
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "A valid email is required." });
    }
    if (!isStrongEnoughPassword(password)) {
      return res.status(400).json({ ok: false, error: "Password must be at least 8 characters." });
    }

    const users = await readUsers();
    const exists = users.some(u => normalizeEmail(u.email) === email);
    if (exists) {
      return res.status(409).json({ ok: false, error: "User already exists. Please sign in." });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const newUser = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeUsers(users);

    // Do not return passwordHash
    return res.status(201).json({
      ok: true,
      user: { id: newUser.id, name: newUser.name, email: newUser.email }
    });
  } catch (err) {
    next(err);
  }
});

app.post("/api/auth/signin", async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "A valid email is required." });
    }
    if (typeof password !== "string") {
      return res.status(400).json({ ok: false, error: "Password is required." });
    }

    const users = await readUsers();
    const user = users.find(u => normalizeEmail(u.email) === email);
    if (!user) {
      return res.status(401).json({ ok: false, error: "Invalid credentials." });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ ok: false, error: "Invalid credentials." });
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({
      ok: true,
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (err) {
    next(err);
  }
});

function requireAuth(req, res, next) {
  const header = String(req.headers.authorization || "");
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({ ok: false, error: "Missing Bearer token." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid or expired token." });
  }
}

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// Error handler (including CORS middleware errors)
app.use((err, req, res, next) => {
  const msg = err?.message || "Server error";
  const isCors = msg.toLowerCase().includes("cors blocked");
  res.status(isCors ? 403 : 500).json({ ok: false, error: msg });
});

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
  console.log(`Allowed origins: ${allowedOrigins.length ? allowedOrigins.join(", ") : "(none)"}`);
});
