import React, { FormEvent, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Finding = { label: string; severity: string; detail: string };
type Result = {
  id: string;
  target: string;
  target_type: string;
  score: number;
  verdict: "low_risk" | "suspicious" | "malicious";
  provider: string;
  cached: boolean;
  scanned_at: string;
  findings: Finding[];
};

const API_URL = (import.meta.env.VITE_API_URL ?? "").replace(/\\\/$/, "");
const verdictLabel = (verdict: Result["verdict"]) => verdict.replace("_", " ");

function App() {
  const [target, setTarget] = useState("");
  const [useVirusTotal, setUseVirusTotal] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [history, setHistory] = useState<Result[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function loadHistory() {
    try {
      const response = await fetch(`${API_URL}/api/scans?limit=10`, { signal: AbortSignal.timeout(8000) });
      if (response.ok) setHistory(await response.json());
    } catch {
      // The scan form surfaces connection errors; history can fail quietly.
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  async function scan(event: FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, share_with_virustotal: useVirusTotal }),
        signal: AbortSignal.timeout(20000),
      });
      const data: Result | { detail?: string } = await response.json();
      if (!response.ok) throw new Error(("detail" in data && data.detail) || "Scan failed");
      const scanResult = data as Result;
      setResult(scanResult);
      setHistory((current) => [scanResult, ...current.filter((item) => item.id !== scanResult.id)].slice(0, 10));
      setTarget("");
    } catch (err) {
      const timedOut = err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError");
      setError(timedOut ? "The API did not respond. Confirm the backend is running and VITE_API_URL is configured when needed." : err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main>
      <nav><span className="brand">THREATSCOPE</span><span className="status">● ANALYSIS ONLINE</span></nav>
      <section className="hero">
        <p className="eyebrow">OPEN THREAT INTELLIGENCE</p>
        <h1>See the risk<br />behind the link.</h1>
        <p className="intro">Inspect a URL, domain, or IP address for security signals and get a clear, explainable verdict.</p>
        <form onSubmit={scan}>
          <input required value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com/path" aria-label="Scan target" />
          <button disabled={loading}>{loading ? "ANALYZING…" : "SCAN TARGET"}</button>
        </form>
        <button
          type="button"
          className={`lookup-toggle ${useVirusTotal ? "active" : ""}`}
          aria-pressed={useVirusTotal}
          onClick={() => setUseVirusTotal((enabled) => !enabled)}
        >
          <span className="toggle-indicator" aria-hidden="true">{useVirusTotal ? "✓" : ""}</span>
          <span><strong>Check an existing VirusTotal report</strong><small>Optional, quota-limited lookup. No new URL is submitted.</small></span>
        </button>
        {error && <p className="error">{error}</p>}
        <p className="scan-note">Local analysis includes structural, DNS, and public RDAP registration checks. VirusTotal is optional, quota-limited, and never receives new URL submissions from ThreatScope.</p>
      </section>

      {result && (
        <section className="result">
          <div>
            <p className="eyebrow">LATEST ANALYSIS</p>
            <h2 title={result.target}>{result.target}</h2>
            <p>Provider: {result.provider}</p>
            {result.cached && <p className="cached">Recent cached result — no provider request used.</p>}
          </div>
          <div className={`score ${result.verdict}`}><strong>{result.score}</strong><span>/100<br />{verdictLabel(result.verdict)}</span></div>
          <div className="findings">
            {result.findings.map((finding) => (
              <article key={finding.label}>
                <span className={`badge ${finding.severity}`}>{finding.severity}</span>
                <div><h3>{finding.label}</h3><p>{finding.detail}</p></div>
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="history">
        <div className="section-heading">
          <div><p className="eyebrow">LOCAL DATABASE</p><h2>Recent scans</h2></div>
          <span>{history.length} stored</span>
        </div>
        {history.length ? (
          <div className="history-list">
            {history.map((item) => (
              <button className="history-row" key={item.id} onClick={() => setResult(item)}>
                <span className={`history-score ${item.verdict}`}>{item.score}</span>
                <span className="history-target"><strong>{item.target}</strong><small>{item.target_type} · {new Date(item.scanned_at).toLocaleString()}</small></span>
                <span className={`verdict ${item.verdict}`}>{verdictLabel(item.verdict)}</span>
              </button>
            ))}
          </div>
        ) : <p className="empty">Your completed scans will appear here.</p>}
      </section>

      <footer>ThreatScope provides security indicators, not a guarantee of safety.</footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
