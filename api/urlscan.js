import { setCORSHeaders, checkRateLimit, validateInput } from "./security.js";

export default async function handler(req, res) {
  setCORSHeaders(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  if (!checkRateLimit(req, res)) return;

  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "Missing url parameter" });
  if (!validateInput("url", url) && !validateInput("domain", url)) {
    return res.status(400).json({ error: "Invalid URL or domain format" });
  }

  const apiKey = process.env.URLSCAN_KEY;
  if (!apiKey) return res.status(500).json({ error: "URLScan API key not configured" });

  try {
    const response = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ url: url.trim(), visibility: "unlisted" }),
    });
    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ error: "URLScan request failed: " + err.message });
  }
}
