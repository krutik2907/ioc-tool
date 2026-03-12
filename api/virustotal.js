export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();

  const { ioc, type } = req.query;
  const apiKey = process.env.REACT_APP_VIRUSTOTAL_KEY;

  if (!apiKey) return res.status(500).json({ error: "VirusTotal API key not configured" });
  if (!ioc || !type) return res.status(400).json({ error: "Missing ioc or type parameter" });

  let endpoint = "";
  if (type === "ip") endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
  else if (type === "domain") endpoint = `https://www.virustotal.com/api/v3/domains/${ioc}`;
  else if (type === "url") {
    const id = Buffer.from(ioc).toString("base64").replace(/=/g, "");
    endpoint = `https://www.virustotal.com/api/v3/urls/${id}`;
  } else if (type === "hash") endpoint = `https://www.virustotal.com/api/v3/files/${ioc}`;

  if (!endpoint) return res.status(400).json({ error: "Unsupported IOC type" });

  try {
    const response = await fetch(endpoint, {
      headers: { "x-apikey": apiKey },
    });
    const data = await response.json();
    res.status(200).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
