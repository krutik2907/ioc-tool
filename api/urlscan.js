export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();

  const { url } = req.query;
  const apiKey = process.env.REACT_APP_URLSCAN_KEY;

  if (!apiKey) return res.status(500).json({ error: "URLScan API key not configured" });
  if (!url) return res.status(400).json({ error: "Missing url parameter" });

  try {
    const response = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "API-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url, visibility: "public" }),
    });
    const data = await response.json();
    res.status(200).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
