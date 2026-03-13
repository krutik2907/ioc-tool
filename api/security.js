// ─── Shared Security Middleware ───────────────────────────────────────────────

// ── CORS: only allow requests from your own Vercel domain ──────────────────
const ALLOWED_ORIGINS = [
  "https://ioc-tool-gnn55o04p-krutik2907s-projects.vercel.app",
  "https://ioc-tool-krutik2907.vercel.app",
  "http://localhost:3000", // for local dev
];

// ── Rate limiting: simple in-memory store (resets on cold start) ───────────
const rateLimitStore = new Map();
const RATE_LIMIT = 30;        // max requests
const RATE_WINDOW = 60 * 1000; // per 60 seconds per IP

// ── Input validation rules ─────────────────────────────────────────────────
const VALIDATORS = {
  ip: /^(\d{1,3}\.){3}\d{1,3}$/,
  domain: /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/,
  url: /^https?:\/\/.{1,500}$/,
  hash: /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/,
};

export function setCORSHeaders(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGINS[0]);
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");
}

export function checkRateLimit(req, res) {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown";
  const now = Date.now();
  const record = rateLimitStore.get(ip) || { count: 0, start: now };

  // Reset window if expired
  if (now - record.start > RATE_WINDOW) {
    record.count = 0;
    record.start = now;
  }

  record.count++;
  rateLimitStore.set(ip, record);

  if (record.count > RATE_LIMIT) {
    res.setHeader("Retry-After", "60");
    res.status(429).json({ error: "Too many requests. Limit: 30 per minute." });
    return false;
  }
  return true;
}

export function validateInput(type, value) {
  if (!value || typeof value !== "string") return false;
  if (value.length > 2000) return false;
  // Strip any control characters or null bytes
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) return false;
  const validator = VALIDATORS[type];
  if (!validator) return false;
  return validator.test(value.trim());
}
