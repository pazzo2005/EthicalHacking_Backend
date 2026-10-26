const bcrypt = require("bcryptjs");

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function normalizeUsername(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function validateSignup({ username, email, password }) {
  if (!username || !email || !password) {
    return "Username, email, and password are required.";
  }
  if (!USERNAME_PATTERN.test(username)) {
    return "Username must be 3–32 characters and use only letters, numbers, or underscores.";
  }
  if (email.length > 254 || !EMAIL_PATTERN.test(email)) {
    return "Enter a valid email address.";
  }
  if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
    return "Password must be between 8 and 72 characters.";
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    return "Password must include a lowercase letter, an uppercase letter, and a number.";
  }
  return null;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    createdAt: user.created_at,
  };
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Authentication required." });
  }
  return next();
}

module.exports = {
  bcrypt,
  normalizeEmail,
  normalizeUsername,
  validateSignup,
  publicUser,
  requireAuth,
};
