require("dotenv").config();

const express = require("express");
const cors = require("cors");
const session = require("express-session");
const db = require("./db");
const SQLiteSessionStore = require("./sessionStore");
const { logRequest, writeLog } = require("./logger");
const {
  bcrypt,
  normalizeEmail,
  normalizeUsername,
  validateSignup,
  publicUser,
  requireAuth,
} = require("./auth");

const app = express();
const port = Number(process.env.PORT) || 4000;
const production = process.env.NODE_ENV === "production";
const frontendOrigin = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret || sessionSecret.length < 32) {
  throw new Error("SESSION_SECRET must be set to a random value at least 32 characters long.");
}
if (production) app.set("trust proxy", 1);

app.disable("x-powered-by");
app.use(cors({ origin: frontendOrigin, credentials: true }));
app.use(logRequest);
app.use(express.json({ limit: "10kb" }));
app.use(session({
  name: "cyberlab.sid",
  secret: sessionSecret,
  store: new SQLiteSessionStore(db),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: production,
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

const findByEmail = db.prepare("SELECT * FROM users WHERE email = ?");
const findById = db.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?");
const insertUser = db.prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
const findDuplicate = db.prepare("SELECT username, email FROM users WHERE username = ? OR email = ?");

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

app.post("/api/client-logs", (req, res) => {
  const allowedEvents = new Set(["page_view", "ui_click", "javascript_error", "unhandled_rejection", "react_error"]);
  const { event, path: pagePath, message, source } = req.body || {};
  if (!allowedEvents.has(event)) return res.status(400).json({ error: "Unsupported log event." });

  const details = {};
  if (typeof pagePath === "string") details.page = pagePath.slice(0, 200);
  if (typeof message === "string") details.message = message.slice(0, 1000);
  if (typeof source === "string") details.source = source.slice(0, 200);
  writeLog(event.endsWith("error") || event === "unhandled_rejection" ? "error" : "info", event, details);
  return res.status(204).end();
});

app.post("/api/auth/signup", async (req, res, next) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const validationError = validateSignup({ username, email, password });
    if (validationError) return res.status(400).json({ error: validationError });

    const duplicate = findDuplicate.get(username, email);
    if (duplicate) {
      if (duplicate.username === username) return res.status(409).json({ error: "That username is already in use." });
      return res.status(409).json({ error: "An account with that email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = insertUser.run(username, email, passwordHash);
    const user = findById.get(result.lastInsertRowid);
    return res.status(201).json({ message: "Account created successfully.", user: publicUser(user) });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "That username or email is already in use." });
    }
    return next(error);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

    const user = findByEmail.get(email);
    const passwordMatches = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!passwordMatches) return res.status(401).json({ error: "Invalid email or password." });

    req.session.regenerate((error) => {
      if (error) return next(error);
      req.session.userId = user.id;
      req.session.save((saveError) => {
        if (saveError) return next(saveError);
        return res.json({ message: "Login successful.", user: publicUser(user) });
      });
    });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  const user = findById.get(req.session.userId);
  if (!user) {
    return req.session.destroy(() => res.status(401).json({ error: "Authentication required." }));
  }
  return res.json({ user: publicUser(user) });
});

app.post("/api/auth/logout", requireAuth, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("cyberlab.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: production,
    });
    return res.json({ message: "Logged out successfully." });
  });
});

app.use((error, req, res, next) => {
  writeLog("error", "server_error", {
    method: req.method,
    path: req.path,
    message: error.message,
    stack: error.stack,
  });
  console.error(error);
  if (res.headersSent) return next(error);
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Request body must be valid JSON." });
  }
  return res.status(500).json({ error: "An unexpected server error occurred." });
});

app.listen(port, () => {
  writeLog("info", "server_started", { port, environment: production ? "production" : "development" });
  console.log(`CyberLab API listening on http://localhost:${port}`);
});
