import React, { FormEvent, useState } from "react";
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

function App() {
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function scan(event: FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await fetch("http://localhost:8000/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Scan failed");
      setResult(data);
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
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com or https://example.com" aria-label="Scan target" />
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

      <footer>ThreatScope provides security indicators, not a guarantee of safety.</footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
