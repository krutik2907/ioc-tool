import { setCORSHeaders, checkRateLimit, validateInput } from "./security.js";

export default async function handler(req, res) {
  // ── CORS ──────────────────────────────────────────────────────────────────
  setCORSHeaders(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  // ── Rate Limiting ─────────────────────────────────────────────────────────
  if (!checkRateLimit(req, res)) return;

  // ── Input Validation ──────────────────────────────────────────────────────
  const { ioc, type } = req.query;
  if (!ioc || !type) return res.status(400).json({ error: "Missing ioc or type parameter" });

  const allowedTypes = ["ip", "domain", "url", "hash"];
  if (!allowedTypes.includes(type)) return res.status(400).json({ error: "Invalid type" });
  if (!validateInput(type, ioc)) return res.status(400).json({ error: `Invalid ${type} format` });

  // ── API Key ───────────────────────────────────────────────────────────────
  const apiKey = process.env.VIRUSTOTAL_KEY;
  if (!apiKey) return res.status(500).json({ error: "VirusTotal API key not configured" });

  // ── Build Endpoint ────────────────────────────────────────────────────────
  let endpoint = "";
  const sanitized = ioc.trim();
  if (type === "ip") endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(sanitized)}`;
  else if (type === "domain") endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(sanitized)}`;
  else if (type === "url") {
    const id = Buffer.from(sanitized).toString("base64").replace(/=/g, "");
    endpoint = `https://www.virustotal.com/api/v3/urls/${id}`;
  } else if (type === "hash") endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(sanitized)}`;

  try {
    const response = await fetch(endpoint, { headers: { "x-apikey": apiKey } });
    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ error: "VirusTotal request failed: " + err.message });
  }
}
