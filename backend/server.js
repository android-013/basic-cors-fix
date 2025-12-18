const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

const isProd = (process.env.NODE_ENV || "").toLowerCase() === "production";

const PORT = isProd
  ? Number(process.env.PORT_PROD || 8080)
  : Number(process.env.PORT_LOCAL || 4000);

const CLIENT_ORIGIN = isProd
  ? (process.env.CLIENT_ORIGIN_PROD || "")
  : (process.env.CLIENT_ORIGIN_LOCAL || "");

const CORS_MODE = process.env.CORS_MODE || "broken";
const BROKEN_ORIGIN = process.env.BROKEN_ORIGIN || "http://localhost:3000";

const allowedOrigins =
  CORS_MODE === "fixed"
    ? [CLIENT_ORIGIN]
    : [BROKEN_ORIGIN];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`), false);
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Debug-Header", "Authorization"]
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

app.get("/api/ping", (req, res) => {
  res.json({
    ok: true,
    env: isProd ? "production" : "development",
    mode: CORS_MODE,
    allowedOrigins,
    time: new Date().toISOString()
  });
});

app.post("/api/login", (req, res) => {
  res.cookie("session", "demo-session", {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd
  });
  res.json({ ok: true, message: "Session cookie set" });
});

app.get("/api/me", (req, res) => {
  res.json({ ok: true, hasSession: Boolean(req.cookies.session) });
});

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ ok: false, error: err.message });
});

app.listen(PORT, () => {
  console.log(`Backend: http://localhost:${PORT}`);
  console.log(`NODE_ENV=${process.env.NODE_ENV} | CORS_MODE=${CORS_MODE}`);
  console.log(`Allowed origins: ${allowedOrigins.join(", ")}`);
});
