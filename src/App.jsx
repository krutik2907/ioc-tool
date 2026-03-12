/* eslint no-unused-vars: ["error", { "varsIgnorePattern": "^mockEnrich$" }] */
import { useState, useCallback } from "react";

// ─── MITRE ATT&CK Mapping Database ───────────────────────────────────────────
const MITRE_MAP = {
  ip: [
    {
      id: "T1071",
      name: "Application Layer Protocol",
      tactic: "Command and Control",
      description: "Adversaries may communicate using application layer protocols to avoid detection/network filtering.",
      mitigation: "M1031 – Network Intrusion Prevention: Use network-based intrusion prevention systems to identify and block malicious traffic. M1037 – Filter Network Traffic: Use network appliances to filter ingress/egress traffic.",
    },
    {
      id: "T1090",
      name: "Proxy",
      tactic: "Command and Control",
      description: "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary.",
      mitigation: "M1031 – Network Intrusion Prevention. M1037 – Filter Network Traffic: Block known proxy infrastructure.",
    },
    {
      id: "T1046",
      name: "Network Service Discovery",
      tactic: "Discovery",
      description: "Adversaries may attempt to get a listing of services running on remote hosts.",
      mitigation: "M1042 – Disable or Remove Feature or Program. M1031 – Network Intrusion Prevention.",
    },
  ],
  url: [
    {
      id: "T1566.002",
      name: "Phishing: Spearphishing Link",
      tactic: "Initial Access",
      description: "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access.",
      mitigation: "M1054 – Software Configuration: Use anti-spoofing and email authentication. M1017 – User Training: Train users to identify phishing attempts.",
    },
    {
      id: "T1189",
      name: "Drive-by Compromise",
      tactic: "Initial Access",
      description: "Adversaries may gain access through a user visiting a website during normal browsing.",
      mitigation: "M1050 – Exploit Protection: Enable browser sandboxing. M1021 – Restrict Web-Based Content: Use web filtering.",
    },
    {
      id: "T1204.001",
      name: "User Execution: Malicious Link",
      tactic: "Execution",
      description: "Adversaries may rely upon a user clicking a malicious link to gain execution.",
      mitigation: "M1038 – Execution Prevention. M1017 – User Training.",
    },
  ],
  domain: [
    {
      id: "T1568",
      name: "Dynamic Resolution",
      tactic: "Command and Control",
      description: "Adversaries may dynamically establish connections to command and control infrastructure using DNS.",
      mitigation: "M1031 – Network Intrusion Prevention. M1021 – Restrict Web-Based Content: Block known malicious domains via DNS sinkholes.",
    },
    {
      id: "T1583.001",
      name: "Acquire Infrastructure: Domains",
      tactic: "Resource Development",
      description: "Adversaries may acquire domains that can be used during targeting.",
      mitigation: "M1056 – Pre-compromise: This technique cannot be easily mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses.",
    },
    {
      id: "T1071.004",
      name: "Application Layer Protocol: DNS",
      tactic: "Command and Control",
      description: "Adversaries may communicate using the DNS protocol to avoid detection.",
      mitigation: "M1037 – Filter Network Traffic: Block DNS traffic that does not follow expected patterns. M1031 – Network Intrusion Prevention.",
    },
  ],
  hash: [
    {
      id: "T1204.002",
      name: "User Execution: Malicious File",
      tactic: "Execution",
      description: "Adversaries may rely upon a user opening a malicious file to gain execution.",
      mitigation: "M1038 – Execution Prevention: Use application control solutions. M1017 – User Training.",
    },
    {
      id: "T1027",
      name: "Obfuscated Files or Information",
      tactic: "Defense Evasion",
      description: "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
      mitigation: "M1049 – Antivirus/Antimalware. M1040 – Behavior Prevention on Endpoint.",
    },
    {
      id: "T1055",
      name: "Process Injection",
      tactic: "Defense Evasion / Privilege Escalation",
      description: "Adversaries may inject code into processes to evade process-based defenses.",
      mitigation: "M1040 – Behavior Prevention on Endpoint. M1026 – Privileged Account Management.",
    },
  ],
};

// ─── IOC Type Detection ───────────────────────────────────────────────────────
function detectIOCType(value) {
  const v = value.trim();
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(v)) return "hash";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return "ip";
  if (/^https?:\/\//i.test(v)) return "url";
  if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}/.test(v)) return "domain";
  return "unknown";
}


// ─── Live API enrichment via Vercel serverless proxy ─────────────────────────
// Keys are stored server-side only in Vercel env vars — never exposed to browser
async function enrichIOC(ioc, type) {
  const result = {
    ioc, type,
    verdict: "Unknown",
    riskScore: 0,
    mitre: MITRE_MAP[type] || [],
    tags: [],
    errors: [],
  };

  // VirusTotal via /api/virustotal
  try {
    const res = await fetch(`/api/virustotal?ioc=${encodeURIComponent(ioc)}&type=${type}`);
    const data = await res.json();
    if (data?.error) throw new Error(data.error);
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (stats) {
      const malicious = stats.malicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      result.vtDetections = `${malicious}/${total}`;
      result.riskScore = Math.round((malicious / total) * 100);
      result.verdict = malicious > 5 ? "Malicious" : malicious > 0 ? "Suspicious" : "Clean";
      result.country = data?.data?.attributes?.country || null;
      result.lastSeen = data?.data?.attributes?.last_modification_date
        ? new Date(data.data.attributes.last_modification_date * 1000).toISOString().split("T")[0]
        : null;
      const cats = data?.data?.attributes?.categories;
      if (cats) result.tags = Object.values(cats).slice(0, 3);
    }
  } catch (e) {
    result.errors.push("VirusTotal: " + e.message);
  }

  // AbuseIPDB via /api/abuseipdb (IP only)
  if (type === "ip") {
    try {
      const res = await fetch(`/api/abuseipdb?ip=${encodeURIComponent(ioc)}`);
      const data = await res.json();
      if (data?.error) throw new Error(data.error);
      if (data?.data) {
        result.abuseConfidence = data.data.abuseConfidenceScore;
        result.country = result.country || data.data.countryCode;
        result.isp = data.data.isp;
        if (data.data.abuseConfidenceScore > 50) {
          result.riskScore = Math.max(result.riskScore, data.data.abuseConfidenceScore);
          result.verdict = "Malicious";
        }
      }
    } catch (e) {
      result.errors.push("AbuseIPDB: " + e.message);
    }
  }

  // URLScan via /api/urlscan (URL/domain)
  if (type === "url" || type === "domain") {
    try {
      const res = await fetch(`/api/urlscan?url=${encodeURIComponent(ioc)}`);
      const data = await res.json();
      if (data?.uuid) result.urlscanId = data.uuid;
    } catch (e) {
      result.errors.push("URLScan: " + e.message);
    }
  }

  if (!result.riskScore && result.verdict === "Unknown") {
    result.verdict = "No Data";
    result.riskScore = 0;
  }

  return result;
}

// ─── CSV Export ───────────────────────────────────────────────────────────────
function exportCSV(results) {
  const headers = ["IOC", "Type", "Verdict", "Risk Score", "VT Detections", "Abuse Confidence", "Country", "Tags", "MITRE Techniques", "MITRE Tactics", "Mitigations", "Last Seen", "Notes"];
  const rows = results.map((r) => [
    r.ioc, r.type, r.verdict,
    r.riskScore + "%",
    r.vtDetections || "N/A",
    r.abuseConfidence != null ? r.abuseConfidence + "%" : "N/A",
    r.country || "N/A",
    (r.tags || []).join("; "),
    r.mitre.map((m) => `${m.id} - ${m.name}`).join("; "),
    r.mitre.map((m) => m.tactic).join("; "),
    r.mitre.map((m) => m.mitigation).join(" | "),
    r.lastSeen || "N/A",
    r.isMock ? "MOCK DATA" : r.errors?.join(", ") || "",
  ]);
  const csv = [headers, ...rows].map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ioc_enrichment_${new Date().toISOString().split("T")[0]}.csv`;
  a.click();
}

// ─── Verdict Badge ────────────────────────────────────────────────────────────
function VerdictBadge({ verdict }) {
  const colors = {
    Malicious: { bg: "#ff2d2d22", border: "#ff2d2d", text: "#ff6b6b" },
    Suspicious: { bg: "#ff9a0022", border: "#ff9a00", text: "#ffb347" },
    Clean: { bg: "#00ff8822", border: "#00ff88", text: "#00ff88" },
    "No Data": { bg: "#ffffff11", border: "#ffffff33", text: "#888" },
    Unknown: { bg: "#ffffff11", border: "#ffffff33", text: "#888" },
  };
  const c = colors[verdict] || colors.Unknown;
  return (
    <span style={{ background: c.bg, border: `1px solid ${c.border}`, color: c.text, padding: "2px 10px", borderRadius: 4, fontSize: 11, fontFamily: "monospace", fontWeight: 700, letterSpacing: 1 }}>
      {verdict.toUpperCase()}
    </span>
  );
}

// ─── Risk Meter ───────────────────────────────────────────────────────────────
function RiskMeter({ score }) {
  const color = score > 70 ? "#ff2d2d" : score > 30 ? "#ff9a00" : "#00ff88";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: "#ffffff11", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: 3, transition: "width 0.8s ease" }} />
      </div>
      <span style={{ color, fontFamily: "monospace", fontSize: 12, minWidth: 32 }}>{score}%</span>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function IOCEnrichmentTool() {
  const [rawInput, setRawInput] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [expandedRow, setExpandedRow] = useState(null);
  const [activeTab, setActiveTab] = useState("input");

  const handleAnalyze = useCallback(async () => {
    const lines = rawInput.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!lines.length) return;
    setLoading(true);
    setResults([]);
    setProgress(0);
    setActiveTab("results");
    const enriched = [];
    for (let i = 0; i < lines.length; i++) {
      const ioc = lines[i];
      const type = detectIOCType(ioc);
      const result = await enrichIOC(ioc, type);
      enriched.push(result);
      setResults([...enriched]);
      setProgress(Math.round(((i + 1) / lines.length) * 100));
    }
    setLoading(false);
  }, [rawInput]);

  const sampleIOCs = `185.220.101.45\n194.165.16.11\nhttps://malware-download.xyz/payload.exe\nevil-phishing-site.ru\n44d88612fea8a8f36de82e1278abb02f`;

  return (
    <div style={{ minHeight: "100vh", background: "#080c14", color: "#c8d8f0", fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
      <div style={{ position: "fixed", inset: 0, backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)", pointerEvents: "none", zIndex: 0 }} />

      <div style={{ position: "relative", zIndex: 1, maxWidth: 1100, margin: "0 auto", padding: "24px 20px" }}>

        {/* Header */}
        <div style={{ borderBottom: "1px solid #1a2a3a", paddingBottom: 20, marginBottom: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
            <div style={{ width: 8, height: 8, background: "#00ff88", borderRadius: "50%", boxShadow: "0 0 8px #00ff88" }} />
            <span style={{ color: "#4a6a8a", fontSize: 11, letterSpacing: 3 }}>SOC ANALYST WORKSTATION v1.0</span>
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, color: "#e8f4ff", margin: 0, letterSpacing: -0.5 }}>
            IOC Bulk Enrichment Tool
          </h1>
          <p style={{ color: "#4a6a8a", fontSize: 12, margin: "6px 0 0", letterSpacing: 1 }}>
            THREAT INTELLIGENCE · MITRE ATT&CK MAPPING · INCIDENT REPORTING
          </p>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 2, marginBottom: 20 }}>
          {["input", "results"].map((tab) => (
            <button key={tab} onClick={() => setActiveTab(tab)}
              style={{ padding: "8px 20px", background: activeTab === tab ? "#0d2035" : "transparent", border: activeTab === tab ? "1px solid #1e3a5a" : "1px solid transparent", color: activeTab === tab ? "#7eb8e8" : "#4a6a8a", borderRadius: 4, cursor: "pointer", fontSize: 11, letterSpacing: 2, textTransform: "uppercase", transition: "all 0.2s" }}>
              {tab === "input" ? "▶ INPUT" : `◈ RESULTS ${results.length ? `(${results.length})` : ""}`}
            </button>
          ))}
          <div style={{ marginLeft: "auto", padding: "8px 16px", border: "1px solid #1e3a5a", color: "#00ff88", borderRadius: 4, fontSize: 11, letterSpacing: 2 }}>
            🔒 KEYS SECURED
          </div>
        </div>

        {/* Input Tab */}
        {activeTab === "input" && (
          <div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 11, color: "#4a6a8a", letterSpacing: 2 }}>IOC INPUT — one per line (IP, URL, domain, hash)</span>
                <button onClick={() => setRawInput(sampleIOCs)}
                  style={{ background: "transparent", border: "1px solid #1e3a5a", color: "#4a6a8a", padding: "4px 10px", borderRadius: 3, cursor: "pointer", fontSize: 10, letterSpacing: 1 }}>
                  LOAD SAMPLE
                </button>
              </div>
              <textarea value={rawInput} onChange={(e) => setRawInput(e.target.value)}
                placeholder={"185.220.101.45\nhttps://phishing-site.ru/login\nevil-domain.xyz\nd41d8cd98f00b204e9800998ecf8427e"}
                style={{ width: "100%", minHeight: 200, background: "#0a1520", border: "1px solid #1e3a5a", color: "#c8d8f0", padding: 14, borderRadius: 6, fontSize: 13, fontFamily: "monospace", outline: "none", resize: "vertical", lineHeight: 1.8, boxSizing: "border-box" }} />
            </div>
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <button onClick={handleAnalyze} disabled={loading || !rawInput.trim()}
                style={{ background: loading ? "#0a1520" : "#003d1f", border: `1px solid ${loading ? "#1e3a5a" : "#00ff88"}`, color: loading ? "#4a6a8a" : "#00ff88", padding: "10px 28px", borderRadius: 4, cursor: loading ? "not-allowed" : "pointer", fontSize: 12, letterSpacing: 2, fontFamily: "monospace", fontWeight: 700, transition: "all 0.2s" }}>
                {loading ? `ANALYZING... ${progress}%` : "▶ RUN ENRICHMENT"}
              </button>
              {rawInput.trim() && (
                <span style={{ fontSize: 11, color: "#4a6a8a" }}>
                  {rawInput.split("\n").filter(Boolean).length} IOC(s) queued
                </span>
              )}
            </div>
          </div>
        )}

        {/* Results Tab */}
        {activeTab === "results" && (
          <div>
            {loading && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#4a6a8a", marginBottom: 6 }}>
                  <span>ENRICHING IOCs...</span><span>{progress}%</span>
                </div>
                <div style={{ height: 3, background: "#0d2035", borderRadius: 2 }}>
                  <div style={{ width: `${progress}%`, height: "100%", background: "#00ff88", borderRadius: 2, transition: "width 0.3s ease", boxShadow: "0 0 8px #00ff88" }} />
                </div>
              </div>
            )}

            {results.length > 0 && (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 20 }}>
                  {[
                    { label: "TOTAL IOCs", value: results.length, color: "#7eb8e8" },
                    { label: "MALICIOUS", value: results.filter(r => r.verdict === "Malicious").length, color: "#ff6b6b" },
                    { label: "SUSPICIOUS", value: results.filter(r => r.verdict === "Suspicious").length, color: "#ffb347" },
                    { label: "CLEAN", value: results.filter(r => r.verdict === "Clean").length, color: "#00ff88" },
                  ].map(({ label, value, color }) => (
                    <div key={label} style={{ background: "#0a1520", border: "1px solid #1e3a5a", borderRadius: 6, padding: "12px 16px" }}>
                      <div style={{ fontSize: 10, color: "#4a6a8a", letterSpacing: 2, marginBottom: 4 }}>{label}</div>
                      <div style={{ fontSize: 28, fontWeight: 800, color }}>{value}</div>
                    </div>
                  ))}
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
                  <button onClick={() => exportCSV(results)}
                    style={{ background: "#0a1520", border: "1px solid #1e3a5a", color: "#7eb8e8", padding: "8px 16px", borderRadius: 4, cursor: "pointer", fontSize: 11, letterSpacing: 2, fontFamily: "monospace" }}>
                    ↓ EXPORT CSV REPORT
                  </button>
                </div>

                <div style={{ border: "1px solid #1e3a5a", borderRadius: 6, overflow: "hidden" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "2fr 80px 100px 140px 100px 80px", background: "#0a1520", padding: "10px 16px", fontSize: 10, color: "#4a6a8a", letterSpacing: 2, borderBottom: "1px solid #1e3a5a" }}>
                    <span>IOC</span><span>TYPE</span><span>VERDICT</span><span>RISK SCORE</span><span>VT HITS</span><span>COUNTRY</span>
                  </div>
                  {results.map((r, i) => (
                    <div key={i}>
                      <div onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                        style={{ display: "grid", gridTemplateColumns: "2fr 80px 100px 140px 100px 80px", padding: "12px 16px", borderBottom: "1px solid #0d1e2e", cursor: "pointer", background: expandedRow === i ? "#0d1e2e" : "transparent", transition: "background 0.15s" }}>
                        <span style={{ fontSize: 12, color: "#9eb8d8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.ioc}</span>
                        <span style={{ fontSize: 10, color: "#4a8aaa", letterSpacing: 1, alignSelf: "center" }}>{r.type.toUpperCase()}</span>
                        <span style={{ alignSelf: "center" }}><VerdictBadge verdict={r.verdict} /></span>
                        <div style={{ alignSelf: "center" }}><RiskMeter score={r.riskScore} /></div>
                        <span style={{ fontSize: 12, color: "#7eb8e8", alignSelf: "center" }}>{r.vtDetections || "—"}</span>
                        <span style={{ fontSize: 12, color: "#7eb8e8", alignSelf: "center" }}>{r.country || "—"}</span>
                      </div>

                      {expandedRow === i && (
                        <div style={{ background: "#060e18", borderBottom: "1px solid #0d1e2e", padding: "16px 20px" }}>
                          {r.isMock && <div style={{ fontSize: 10, color: "#ff9a00", marginBottom: 12, padding: "6px 10px", background: "#1a100022", border: "1px solid #ff9a0033", borderRadius: 3 }}>⚠ DEMO DATA — Configure API keys for live enrichment</div>}

                          {r.tags?.length > 0 && (
                            <div style={{ marginBottom: 12 }}>
                              <span style={{ fontSize: 10, color: "#4a6a8a", letterSpacing: 2 }}>TAGS: </span>
                              {r.tags.map(t => <span key={t} style={{ fontSize: 10, background: "#0d1e2e", border: "1px solid #1e3a5a", color: "#7eb8e8", padding: "2px 8px", borderRadius: 3, marginLeft: 6 }}>{t}</span>)}
                            </div>
                          )}

                          <div style={{ fontSize: 10, color: "#4a6a8a", letterSpacing: 2, marginBottom: 10 }}>MITRE ATT&CK TECHNIQUES</div>
                          {r.mitre.map((m) => (
                            <div key={m.id} style={{ background: "#0a1520", border: "1px solid #1e3a5a", borderRadius: 4, padding: 12, marginBottom: 8 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                                <span style={{ background: "#001a3a", border: "1px solid #1e5a8a", color: "#4a9ad4", padding: "2px 8px", borderRadius: 3, fontSize: 11, fontWeight: 700 }}>{m.id}</span>
                                <span style={{ color: "#e8f4ff", fontSize: 13, fontWeight: 600 }}>{m.name}</span>
                                <span style={{ marginLeft: "auto", fontSize: 10, color: "#4a6a8a", letterSpacing: 1 }}>{m.tactic.toUpperCase()}</span>
                              </div>
                              <p style={{ margin: "0 0 8px", fontSize: 12, color: "#7a98b8", lineHeight: 1.6 }}>{m.description}</p>
                              <div style={{ borderTop: "1px solid #0d2035", paddingTop: 8 }}>
                                <span style={{ fontSize: 10, color: "#00cc66", letterSpacing: 1 }}>MITIGATION: </span>
                                <span style={{ fontSize: 11, color: "#5a8a6a" }}>{m.mitigation}</span>
                              </div>
                            </div>
                          ))}

                          {r.abuseConfidence != null && (
                            <div style={{ fontSize: 12, color: "#7a98b8", marginTop: 8 }}>
                              <span style={{ color: "#4a6a8a", letterSpacing: 1, fontSize: 10 }}>ABUSEIPDB CONFIDENCE: </span>
                              <span style={{ color: r.abuseConfidence > 50 ? "#ff6b6b" : "#ffb347" }}>{r.abuseConfidence}%</span>
                            </div>
                          )}

                          {r.errors?.length > 0 && (
                            <div style={{ marginTop: 8, fontSize: 10, color: "#ff6b6b" }}>
                              ⚠ Errors: {r.errors.join(", ")}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </>
            )}

            {!loading && results.length === 0 && (
              <div style={{ textAlign: "center", padding: "60px 0", color: "#2a4a6a" }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>◈</div>
                <div style={{ fontSize: 12, letterSpacing: 2 }}>NO RESULTS YET — RUN ENRICHMENT FROM INPUT TAB</div>
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: 32, paddingTop: 16, borderTop: "1px solid #0d1e2e", display: "flex", justifyContent: "space-between", fontSize: 10, color: "#2a4a6a", letterSpacing: 1 }}>
          <span>IOC ENRICHMENT TOOL · SOC ANALYST PORTFOLIO PROJECT</span>
          <span>MITRE ATT&CK® FRAMEWORK v14</span>
        </div>
      </div>
    </div>
  );
}
