const fs = require("node:fs");
const path = require("node:path");

const logDirectory = path.join(__dirname, "..", "logs");
const logFile = path.join(logDirectory, "site.log");
fs.mkdirSync(logDirectory, { recursive: true });

function writeLog(level, event, details = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...details,
  };

  try {
    fs.appendFileSync(logFile, `${JSON.stringify(entry)}\n`, "utf8");
  } catch (error) {
    console.error("Unable to write site log:", error.message);
  }
}

function logRequest(req, res, next) {
  const startedAt = Date.now();
  res.on("finish", () => {
    writeLog(res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "info", "http_request", {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - startedAt,
    });
  });
  next();
}

module.exports = { logFile, logRequest, writeLog };
