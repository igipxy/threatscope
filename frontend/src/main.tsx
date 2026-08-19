import React, { FormEvent, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Finding = { label: string; severity: string; detail: string };
type Result = {
  id: string;
  target: string;
  target_type: string;
  score: number;
  verdict: "clean" | "suspicious" | "malicious";
  provider: string;
  scanned_at: string;
  findings: Finding[];
};

const API_URL = "http://localhost:8000";

function App() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [history, setHistory] = useState<Result[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function loadHistory() {
    try {
      const response = await fetch(`${API_URL}/api/scans?limit=10`);
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
        body: JSON.stringify({ target }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Scan failed");
      setResult(data);
      setHistory((current) => [data, ...current.filter((item) => item.id !== data.id)].slice(0, 10));
      setTarget("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
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
          <input required value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com or https://example.com" aria-label="Scan target" />
          <button disabled={loading}>{loading ? "ANALYZING…" : "SCAN TARGET"}</button>
        </form>
        {error && <p className="error">{error}</p>}
      </section>

      {result && (
        <section className="result">
          <div>
            <p className="eyebrow">LATEST ANALYSIS</p>
            <h2>{result.target}</h2>
            <p>Provider: {result.provider}</p>
          </div>
          <div className={`score ${result.verdict}`}><strong>{result.score}</strong><span>/100<br />{result.verdict}</span></div>
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
                <span className={`verdict ${item.verdict}`}>{item.verdict}</span>
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
