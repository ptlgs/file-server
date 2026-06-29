import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import { generateToken } from "./generateJwt.js";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendPath = path.join(__dirname, "frontend");

// Generate a secure session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Store active sessions (in production, use Redis or a database)
const activeSessions = new Map();

function parsePasswordList(value) {
  if (!value) {
    return [];
  }

  const trimmedValue = value.trim();
  if (!trimmedValue) {
    return [];
  }

  if (trimmedValue.startsWith("[")) {
    try {
      const parsedValue = JSON.parse(trimmedValue);
      if (Array.isArray(parsedValue)) {
        return parsedValue.map(String).filter(Boolean);
      }
      console.error("FRONTEND_PASSWORDS must be a comma-separated list or JSON array.");
      return [];
    } catch (error) {
      console.error("FRONTEND_PASSWORDS must be a comma-separated list or JSON array.");
      return [];
    }
  }

  return value.split(",").map(password => password.trim()).filter(Boolean);
}

function getFrontendPasswords() {
  return [
    ...parsePasswordList(process.env.FRONTEND_PASSWORDS),
    ...(process.env.FRONTEND_PASSWORD ? [process.env.FRONTEND_PASSWORD] : [])
  ];
}

// Secure password comparison (constant-time for equal-length inputs)
function secureCompare(a, b) {
    if (typeof a !== "string" || typeof b !== "string") {
        return false;
    }

    const aBuffer = Buffer.from(a);
    const bBuffer = Buffer.from(b);
    if (aBuffer.length !== bBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function isValidFrontendPassword(password, configuredPasswords) {
  let isValid = false;
  for (const configuredPassword of configuredPasswords) {
    isValid = secureCompare(password, configuredPassword) || isValid;
  }
  return isValid;
}

app.get("/api/main-server-url", (req, res) => {
  res.json({ url: process.env.MAIN_SERVER_URL || "http://localhost:3000" });
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(frontendPath, "login.html"));
});

app.post("/login", (req, res) => {
  const { password } = req.body;
  const frontendPasswords = getFrontendPasswords();

  if (frontendPasswords.length === 0) {
    console.error("FRONTEND_PASSWORD or FRONTEND_PASSWORDS is not set in environment variables.");
    return res.status(500).send("Server configuration error.");
  }

  try {
    if (isValidFrontendPassword(password, frontendPasswords)) {
      // Generate a secure session ID
      const sessionId = generateSessionId();

      // Store session with timestamp
      activeSessions.set(sessionId, {
        createdAt: Date.now(),
        lastAccessed: Date.now()
      });

      // Set secure session cookie
      res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        path: '/'
      });

      res.redirect("/");
    } else {
      res.status(401).send(`
        <h1>Login Failed</h1>
        <p>Incorrect password. Please <a href="/login">try again</a>.</p>
      `);
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send("An error occurred during login.");
  }
});

// Enhanced authentication middleware
function isAuthenticated(req, res, next) {
  const sessionId = req.cookies.sessionId;
  const session = activeSessions.get(sessionId);

  if (!session) {
    // Clear invalid session cookie
    res.clearCookie('sessionId');
    return false;
  }

  // Check session age (24 hours)
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    activeSessions.delete(sessionId);
    res.clearCookie('sessionId');
    return false;
  }

  // Update last accessed time
  session.lastAccessed = Date.now();
  return true;
}

app.get("/", (req, res) => {
  if (isAuthenticated(req, res)) {
    res.sendFile(path.join(frontendPath, "upload.html"));
  } else {
    res.redirect("/login");
  }
});

app.get("/api/token", (req, res) => {
  if (isAuthenticated(req, res)) {
    const token = generateToken();
    res.json({ token });
  } else {
    res.status(403).json({ error: "Forbidden" });
  }
});

// Add logout endpoint
app.post("/logout", (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId) {
    activeSessions.delete(sessionId);
    res.clearCookie('sessionId');
  }
  res.redirect("/login");
});

const FRONTEND_PORT = parseInt(process.env.FRONTEND_PORT || "4000");
app.listen(FRONTEND_PORT, () => {
  console.log(`Frontend server running on port ${FRONTEND_PORT}`);
});
