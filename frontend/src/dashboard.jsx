import React, { useState } from "react";

const TABS = ["domain", "number", "sip"];

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState("domain");

  const [domainInput, setDomainInput] = useState("");
  const [domainResult, setDomainResult] = useState(null);
  const [domainLoading, setDomainLoading] = useState(false);

  const [numberInput, setNumberInput] = useState("");
  const [numberResult, setNumberResult] = useState(null);
  const [numberLoading, setNumberLoading] = useState(false);

  const [sipInput, setSipInput] = useState("");
  const [sipResult, setSipResult] = useState(null);
  const [sipLoading, setSipLoading] = useState(false);
  const [sipFile, setSipFile] = useState(null);

  const [error, setError] = useState(null);

  const apiBase = "http://localhost:5000";

  // ========== DOMAIN SUBMIT ==========
  async function handleDomainSubmit(e) {
    e.preventDefault();
    setError(null);
    setDomainLoading(true);
    setDomainResult(null);
    try {
      const res = await fetch(`${apiBase}/api/domain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domainInput }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Domain lookup failed");
      setDomainResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setDomainLoading(false);
    }
  }

  // ========== NUMBER SUBMIT ==========
  async function handleNumberSubmit(e) {
    e.preventDefault();
    setError(null);
    setNumberLoading(true);
    setNumberResult(null);
    try {
      const res = await fetch(`${apiBase}/api/number`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ number: numberInput }), // Flask expects "number"
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Number lookup failed");
      setNumberResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setNumberLoading(false);
    }
  }

  // ========== SIP SUBMIT ==========
async function handleSipSubmit(e) {
  e.preventDefault();
  setError(null);
  setSipLoading(true);
  setSipResult(null);
  try {
    let res;

    if (sipFile) {
      const formData = new FormData();
      formData.append("file", sipFile);
      // optional: also send pasted text as extra context
      if (sipInput.trim()) {
        formData.append("sip_text_fallback", sipInput);
      }
      res = await fetch(`${apiBase}/api/sip`, {
        method: "POST",
        body: formData,
      });
    } else {
      res = await fetch(`${apiBase}/api/sip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sip_text: sipInput }),
      });
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "SIP analysis failed");
    setSipResult(data);
  } catch (err) {
    setError(err.message);
  } finally {
    setSipLoading(false);
  }
}

  // ========== SCORE PILL ==========
  function renderScoreBadge(scoreLabel, numeric) {
    if (!scoreLabel) return null;
    const base = "score-pill";
    const score = String(scoreLabel).toLowerCase();

    const content =
      numeric != null
        ? `${score.toUpperCase()} • ${numeric}`
        : score.toUpperCase();

    if (score === "high") {
      return <span className={`${base} score-high`}>{content}</span>;
    }
    if (score === "medium") {
      return <span className={`${base} score-medium`}>{content}</span>;
    }
    return <span className={`${base} score-low`}>{content}</span>;
  }

  return (
    <div className="app-shell">
      {/* HEADER */}
      <header className="app-header">
        <div className="app-header-title">
          <h1 className="cg-dashboard-title">CallGraph OSINT</h1>
          <span>Virtual Number & VoIP Intelligence & Real‑time Threat Recon Console</span>
        </div>
        <div className="app-header-pill">
          <span className="app-header-dot" />
          <span>Backend live</span>
        </div>
      </header>

      {/* MAIN */}
      <main className="app-main">
        {/* Tabs */}
        <div
          style={{
            marginBottom: "14px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div className="tab-strip">
            <button
              type="button"
              className={`tab-pill ${activeTab === "domain" ? "active" : ""}`}
              onClick={() => setActiveTab("domain")}
            >
              Domain
            </button>
            <button
              type="button"
              className={`tab-pill ${activeTab === "number" ? "active" : ""}`}
              onClick={() => setActiveTab("number")}
            >
              Number
            </button>
            <button
              type="button"
              className={`tab-pill ${activeTab === "sip" ? "active" : ""}`}
              onClick={() => setActiveTab("sip")}
            >
              SIP / IP
            </button>
          </div>
        </div>

        {error && <div className="toast">{error}</div>}

        <div className="dashboard-grid">
          {/* LEFT: ACTIVE TOOL CARD */}
          <section className="card">
            <div className="card-head">
              <div className="card-title">
                {activeTab === "domain" && "Domain reconnaissance"}
                {activeTab === "number" && "Number intelligence"}
                {activeTab === "sip" && "SIP & IP analysis"}
              </div>
              <div className="card-tag">{activeTab.toUpperCase()}</div>
            </div>

            {activeTab === "domain" && (
              <>
                <div className="field-group">
                  <label className="field-label">Target domain</label>
                  <p className="field-description">
                    Analyze whois, DNS and platform heuristics for VoIP‑style
                    domains.
                  </p>
                  <div className="input-shell">
                    <input
                      type="text"
                      value={domainInput}
                      onChange={(e) => setDomainInput(e.target.value)}
                      className="input-control"
                      placeholder="voip-example.com"
                      required
                    />
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={handleDomainSubmit}
                  disabled={domainLoading}
                >
                  {domainLoading ? "Scanning domain…" : "Run domain scan"}
                </button>
                {domainLoading && <div className="loader-line" />}
              </>
            )}

            {activeTab === "number" && (
              <>
                <div className="field-group">
                  <label className="field-label">Phone number</label>
                  <p className="field-description">
                    Validate type, carrier, VOIP flags and risk using Twilio
                    Lookup.
                  </p>
                  <div className="input-shell">
                    <input
                      type="text"
                      value={numberInput}
                      onChange={(e) => setNumberInput(e.target.value)}
                      className="input-control"
                      placeholder="+14155552671"
                      required
                    />
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={handleNumberSubmit}
                  disabled={numberLoading}
                >
                  {numberLoading ? "Tracing…" : "Run number trace"}
                </button>
                {numberLoading && <div className="loader-line" />}
              </>
            )}

           {activeTab === "sip" && (
  <>
    <div className="field-group">
      <label className="field-label">SIP logs</label>
      <p className="field-description">
        Paste INVITE / REGISTER traffic or upload a .pcap/.pcapng capture to detect spoofing, open SIP ports and IP origin.
      </p>
      <div className="input-shell">
        <textarea
          value={sipInput}
          onChange={(e) => setSipInput(e.target.value)}
          className="textarea-control"
          placeholder="Paste SIP INVITE / REGISTER logs here…"
        />
      </div>
    </div>

    <div className="field-group">
      <label className="field-label">Or upload capture</label>
      <p className="field-description">
        Supports .pcap / .pcapng or plain .txt SIP logs.
      </p>
      <input
        type="file"
        accept=".pcap,.pcapng,.txt,.log"
        onChange={(e) => {
          const file = e.target.files?.[0] || null;
          setSipFile(file);
        }}
      />
    </div>

    <button
      type="button"
      className="btn-primary"
      onClick={handleSipSubmit}
      disabled={sipLoading}
    >
      {sipLoading ? "Analyzing…" : "Run SIP analysis"}
    </button>
    {sipLoading && <div className="loader-line" />}
  </>
)}

          </section>

          {/* RIGHT: RESULT / INTEL CARD */}
          <section className="card">
            <div className="card-head">
              <div className="card-title">Intel stream</div>
            </div>

            <div className="result-panel">
              {/* DOMAIN RESULTS */}
              {activeTab === "domain" && (
                <>
                  {!domainResult && (
                    <p className="result-summary">
                      Submit a domain to see whois, DNS and threat scoring here.
                    </p>
                  )}

                  {domainResult && domainResult.error && (
                    <p
                      className="result-summary"
                      style={{ color: "#f97373" }}
                    >
                      {domainResult.error}
                    </p>
                  )}

                  {domainResult && !domainResult.error && (
                    <>
                      <div className="result-kv">
                        <div className="result-kv-key">Summary</div>
                        <div className="result-kv-value">
                          {domainResult.summary}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Domain</div>
                        <div className="result-kv-value">
                          {domainResult.domain}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Registrar</div>
                        <div className="result-kv-value">
                          {domainResult.whois?.registrar}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Creation date</div>
                        <div className="result-kv-value">
                          {domainResult.whois?.creation_date}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Country</div>
                        <div className="result-kv-value">
                          {domainResult.whois?.country}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Age (days)</div>
                        <div className="result-kv-value">
                          {domainResult.age_days ?? "Unknown"}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">A records</div>
                        <div className="result-kv-value">
                          {domainResult.dns?.ips?.length
                            ? domainResult.dns.ips.join(", ")
                            : "None"}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Platform</div>
                        <div className="result-kv-value">
                          {domainResult.platform}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Threat</div>
                        <div className="result-kv-value">
                          {renderScoreBadge(domainResult.score, null)}
                        </div>
                      </div>
                      <div className="result-summary">
                        Raw payload:
                        <pre style={{ marginTop: 6 }}>
                          {JSON.stringify(domainResult, null, 2)}
                        </pre>
                      </div>
                    </>
                  )}
                </>
              )}

              {/* NUMBER RESULTS */}
              {activeTab === "number" && (
                <>
                  {!numberResult && (
                    <p className="result-summary">
                      Submit a phone number to see carrier, VOIP flags and risk.
                    </p>
                  )}

                  {numberResult && numberResult.error && (
                    <p
                      className="result-summary"
                      style={{ color: "#f97373" }}
                    >
                      {numberResult.error}
                    </p>
                  )}

                  {numberResult && !numberResult.error && (
                    <>
                      <div className="result-kv">
                        <div className="result-kv-key">Summary</div>
                        <div className="result-kv-value">
                          {numberResult.summary}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Input</div>
                        <div className="result-kv-value">
                          {numberResult.input}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Normalized</div>
                        <div className="result-kv-value">
                          {numberResult.normalized}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Country</div>
                        <div className="result-kv-value">
                          {numberResult.country_name ||
                            numberResult.country_iso2 ||
                            "Unknown"}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Calling code</div>
                        <div className="result-kv-value">
                          {numberResult.country_code ?? "Unknown"}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Line type</div>
                        <div className="result-kv-value">
                          {numberResult.type || "Unknown"}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Carrier</div>
                        <div className="result-kv-value">
                          {numberResult.carrier_hint || "Unknown"}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Valid</div>
                        <div className="result-kv-value">
                          {String(numberResult.valid)}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Reassignment</div>
                        <div className="result-kv-value">
                          {numberResult.reassigned_recently || "Unknown"}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Social footprint</div>
                        <div className="result-kv-value">
                          {Array.isArray(numberResult.social_platforms) &&
                          numberResult.social_platforms.length > 0
                            ? numberResult.social_platforms.join(", ")
                            : "None detected"}
                        </div>
                      </div>

                      <div className="result-kv">
                        <div className="result-kv-key">Threat</div>
                        <div className="result-kv-value">
                          {renderScoreBadge(
                            numberResult.threat_score_label ||
                              numberResult.score,
                            numberResult.threat_score_numeric
                          )}
                        </div>
                      </div>

                      <div className="result-summary">
                        Raw payload:
                        <pre style={{ marginTop: 6 }}>
                          {JSON.stringify(numberResult, null, 2)}
                        </pre>
                      </div>
                    </>
                  )}
                </>
              )}

              {/* SIP RESULTS */}
              {activeTab === "sip" && (
                <>
                  {!sipResult && (
                    <p className="result-summary">
                      Paste SIP logs to see spoofing detection, open ports and
                      IP geo.
                    </p>
                  )}

                  {sipResult && sipResult.error && (
                    <p
                      className="result-summary"
                      style={{ color: "#f97373" }}
                    >
                      {sipResult.error}
                    </p>
                  )}

                  {sipResult && !sipResult.error && (
                    <>
                      <div className="result-kv">
                        <div className="result-kv-key">Summary</div>
                        <div className="result-kv-value">
                          {sipResult.summary}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">From</div>
                        <div className="result-kv-value">
                          {sipResult.from_uri}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">To</div>
                        <div className="result-kv-value">
                          {sipResult.to_uri}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Spoofing</div>
                        <div className="result-kv-value">
                          {sipResult.spoofing ? "Detected" : "Not detected"}
                        </div>
                      </div>
                      <div className="result-kv">
                        <div className="result-kv-key">Threat</div>
                        <div className="result-kv-value">
                          {renderScoreBadge(sipResult.score, null)}
                        </div>
                      </div>

                      {Array.isArray(sipResult.reasons) &&
                        sipResult.reasons.length > 0 && (
                          <div className="result-kv">
                            <div className="result-kv-key">Reasons</div>
                            <div className="result-kv-value">
                              <ul style={{ paddingLeft: "1rem", margin: 0 }}>
                                {sipResult.reasons.map((r, idx) => (
                                  <li key={idx}>{r}</li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        )}

                      <div className="result-summary" style={{ marginTop: 10 }}>
                        <div
                          style={{
                            marginBottom: 6,
                            fontSize: "0.72rem",
                          }}
                        >
                          IP intelligence
                        </div>
                        <table
                          style={{
                            width: "100%",
                            fontSize: "0.74rem",
                            borderCollapse: "collapse",
                          }}
                        >
                          <thead>
                            <tr>
                              <th
                                style={{
                                  textAlign: "left",
                                  padding: "4px 6px",
                                }}
                              >
                                IP
                              </th>
                              <th
                                style={{
                                  textAlign: "left",
                                  padding: "4px 6px",
                                }}
                              >
                                Open ports
                              </th>
                              <th
                                style={{
                                  textAlign: "left",
                                  padding: "4px 6px",
                                }}
                              >
                                Geo / Org
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {Array.isArray(sipResult.ips) &&
                              sipResult.ips.map((ip) => {
                                const ports =
                                  (sipResult.open_ports &&
                                    sipResult.open_ports[ip]) ||
                                  [];
                                const geo =
                                  (sipResult.ip_geo &&
                                    sipResult.ip_geo[ip]) ||
                                  {};
                                const country =
                                  geo.country || geo.country_name || "Unknown";
                                const city = geo.city || "";
                                const org = geo.org || "";
                                const parts = [country, city, org].filter(
                                  Boolean
                                );
                                const loc = parts.join(", ");
                                return (
                                  <tr key={ip}>
                                    <td style={{ padding: "3px 6px" }}>{ip}</td>
                                    <td style={{ padding: "3px 6px" }}>
                                      {ports && ports.length
                                        ? ports.join(", ")
                                        : "None"}
                                    </td>
                                    <td style={{ padding: "3px 6px" }}>
                                      {loc || "Unknown"}
                                    </td>
                                  </tr>
                                );
                              })}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </>
              )}
            </div>
          </section>
        </div>
      </main>
    </div>
  );
}
