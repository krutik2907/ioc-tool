import { setCORSHeaders, checkRateLimit, validateInput } from "./security.js";

export default async function handler(req, res) {
  setCORSHeaders(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  if (!checkRateLimit(req, res)) return;

  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: "Missing ip parameter" });
  if (!validateInput("ip", ip)) return res.status(400).json({ error: "Invalid IP address format" });

  const apiKey = process.env.ABUSEIPDB_KEY;
  if (!apiKey) return res.status(500).json({ error: "AbuseIPDB API key not configured" });

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip.trim())}&maxAgeInDays=90`,
      { headers: { Key: apiKey, Accept: "application/json" } }
    );
    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ error: "AbuseIPDB request failed: " + err.message });
  }
}
