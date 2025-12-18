const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 4000);
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const allowCredentials = String(process.env.CORS_CREDENTIALS || "false").toLowerCase() === "true";

/**
 * CORS setup:
 * - Allows only origins listed in ALLOWED_ORIGINS
 * - Properly handles preflight (OPTIONS)
 */
app.use(
  cors({
    origin: function (origin, callback) {
      // If you open frontend with file://, origin becomes undefined or "null" depending on the browser.
      // We intentionally reject that to keep behavior predictable.
      if (!origin) {
        return callback(new Error("CORS blocked: missing Origin. Serve frontend via http:// (not file://)."));
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked: Origin not allowed: ${origin}`));
    },
    credentials: allowCredentials,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

// Explicit preflight handler (safe even though cors() also handles it)
app.options("*", cors());

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "Backend is healthy",
    allowedOrigins,
    allowCredentials
  });
});

app.get("/api/hello", (req, res) => {
  res.json({
    message: "Hello from backend",
    time: new Date().toISOString()
  });
});

app.post("/api/echo", (req, res) => {
  res.json({
    received: req.body,
    note: "If this works from the browser, your CORS is configured correctly."
  });
});

// CORS error formatter (so you see the reason in the Network response)
app.use((err, req, res, next) => {
  if (err) {
    return res.status(403).json({
      ok: false,
      error: err.message || "CORS error"
    });
  }
  next();
});

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
  console.log(`Allowed origins: ${allowedOrigins.length ? allowedOrigins.join(", ") : "(none)"}`);
});
