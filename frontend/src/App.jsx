import { useEffect, useRef, useState } from "react";
import { call } from "./api.js";

const DEFAULTS = { thr: 5, win: 10, ns: 22, ne: 6, tz_offset: 0, correlation_minutes: 60, spray_users: 5, rotating_ips: 5, case_insensitive_users: false };
const POLICY = [
  ["thr", "Failures per account to flag"],
  ["win", "Failure window (minutes)"],
  ["spray_users", "Spray: distinct accounts per IP"],
  ["rotating_ips", "Distributed: distinct IPs per account"],
  ["ns", "Off-hours start (0-23)"],
  ["ne", "Off-hours end (0-23)"],
  ["tz_offset", "Schedule UTC offset (e.g. 5.5)"],
  ["correlation_minutes", "Max correlation span (minutes)"],
];
const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const RULES = {
  brute: ["Brute force", "T1110"],
  spray: ["Password spray", "T1110.003"],
  distributed: ["Distributed attempts", "T1110"],
  success_after: ["Success after failures", "T1078"],
  offhours: ["Off-hours login", "T1078"],
  offhours_failure: ["Off-hours failures", "T1110"],
  priv: ["Privilege change", "T1098"],
  proc: ["Suspicious command", "T1059"],
};
const fmt = (s) => s?.replace("T", " ").replace("Z", " UTC");

function RuleChips({ rules }) {
  return rules.map((r) => (
    <span key={r} className="rule" title={`MITRE ATT&CK ${RULES[r]?.[1] ?? ""}`}>{RULES[r]?.[0] ?? r}</span>
  ));
}

// Clickable evidence references: clicking highlights the matching rows in the evidence table.
function Cites({ ids, focus, onPick }) {
  const active = focus.length === ids.length && ids.every((i) => focus.includes(i));
  return (
    <span className="cites">
      {ids.map((id) => (
        <button key={id} className={"cite" + (focus.includes(id) ? " on" : "")} aria-pressed={focus.includes(id)} onClick={() => onPick(active ? [] : ids)} title="Highlight in evidence table">
          {id}
        </button>
      ))}
    </span>
  );
}

function Explanation({ x, focus, onPick }) {
  const e = x.explanation;
  if (!e) return <div className="ai">Not generated yet. The rule-based findings below stand on their own.</div>;
  const s = e.structured;
  if (!s) return <div className="ai">{e.text}</div>;
  const group = (title, items) => items?.length > 0 && (
    <>
      <h4>{title}</h4>
      <ul className="cited">
        {items.map((it, i) => (
          <li key={i}>{it.statement} <Cites ids={it.evidence_ids} focus={focus} onPick={onPick} /></li>
        ))}
      </ul>
    </>
  );
  const withheld = e.unsupported || [];
  return (
    <div className="ai">
      {group("Observations (model, review required)", s.observations)}
      {group("Possible interpretations, not established facts", s.interpretations)}
      {s.limitations?.length > 0 && (<><h4>Limitations for this incident</h4><ul>{s.limitations.map((t, i) => <li key={i}>{t}</li>)}</ul></>)}
      {s.investigation_actions?.length > 0 && (<><h4>Model-proposed steps (older explanation)</h4><ul>{s.investigation_actions.map((t, i) => <li key={i}>{t}</li>)}</ul></>)}
      {withheld.length > 0 && (
        <details className="withheld">
          <summary>{withheld.length} model statement{withheld.length > 1 ? "s" : ""} withheld (unsupported or repeated)</summary>
          <ul>{withheld.map((u, i) => <li key={i}><s>{u.statement}</s> <span className="mut">{u.reason}</span></li>)}</ul>
        </details>
      )}
    </div>
  );
}

export default function App() {
  const [cfg, setCfg] = useState(DEFAULTS);
  const [source, setSource] = useState(null); // { sampleSet } or { files }
  const [sampleSets, setSampleSets] = useState([]);
  const [data, setData] = useState(null);
  const [selId, setSelId] = useState(null);
  const [filter, setFilter] = useState(null);
  const [focus, setFocus] = useState([]);
  const [busy, setBusy] = useState(false);
  const [explaining, setExplaining] = useState(null);
  const [msg, setMsg] = useState("");
  const [toast, setToast] = useState("");
  const [saved, setSaved] = useState([]);
  const [slm, setSlm] = useState(null);
  const evidenceRef = useRef(null);

  const refreshSlm = async () => { try { setSlm(await call("/api/slm/status")); } catch { setSlm({ online: false }); } };
  const refreshHistory = async () => { try { setSaved(await call("/api/analyses")); } catch (e) { setMsg(e.message); } };
  useEffect(() => {
    refreshSlm();
    refreshHistory();
    call("/api/samples").then(setSampleSets).catch(() => {});
  }, []);
  useEffect(() => {
    if (focus.length) evidenceRef.current?.querySelector("tr.focus")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [focus]);
  const flash = (t) => { setToast(t); setTimeout(() => setToast(""), 2200); };

  async function run(src = source, config = cfg) {
    if (!src) return setMsg("Load logs or pick a sample first.");
    setBusy(true); setMsg(""); setFocus([]);
    try {
      const d = await call("/api/analyze", { ...src, config });
      setData(d); setSelId(d.incidents[0]?.id ?? null); setFilter(null);
      refreshHistory();
    } catch (e) { setMsg(e.message); }
    finally { setBusy(false); }
  }
  async function onUpload(e) {
    const picked = Array.from(e.target.files || []);
    if (!picked.length) return;
    if (picked.length > 20 || picked.reduce((n, f) => n + f.size, 0) > 20 * 1024 * 1024) return setMsg("Choose at most 20 files and 20 MB total.");
    try {
      const files = await Promise.all(picked.map(async (f) => ({ filename: f.name, content: await f.text() })));
      const src = { files };
      setSource(src); run(src);
    } catch (err) { setMsg(err.message); }
  }
  function loadSample(id) {
    if (!id) return;
    const set = sampleSets.find((s) => s.id === id);
    const config = { ...cfg, ...set.config };
    setCfg(config);
    const src = { sampleSet: id };
    setSource(src); run(src, config);
  }
  async function restore(id) {
    if (!id) return;
    setBusy(true);
    try {
      const d = await call("/api/analyses/" + id);
      setData(d); setSelId(d.incidents[0]?.id ?? null); setCfg(d.config); setSource(null); setFilter(null); setFocus([]);
      setMsg("Restored saved analysis (read-only). Reload the source files to re-run it.");
    } catch (e) { setMsg(e.message); }
    finally { setBusy(false); }
  }
  async function explain(x) {
    setExplaining(x.id); setMsg("");
    try {
      const result = await call("/api/explain", { analysisId: data.analysisId, incidentId: x.id });
      setData((old) => ({ ...old, incidents: old.incidents.map((i) => (i.id === x.id ? { ...i, explanation: result } : i)) }));
    } catch (e) { setMsg(e.message + " Rule-based findings remain available."); }
    finally { setExplaining(null); }
  }
  async function report(x, format, copy = false) {
    try {
      const r = await fetch(`/api/reports/${data.analysisId}/${x.id}?format=${format}`);
      if (!r.ok) throw new Error("Report download failed");
      const text = await r.text();
      if (copy) { await navigator.clipboard.writeText(text); return flash("Report copied"); }
      const url = URL.createObjectURL(new Blob([text], { type: format === "json" ? "application/json" : "text/markdown" }));
      const a = document.createElement("a");
      a.href = url; a.download = `INC-${x.id}.${format}`; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { setMsg(e.message); }
  }
  const setNum = (key) => (e) => setCfg((old) => ({ ...old, [key]: Number(e.target.value) }));

  const incidents = data?.incidents ?? [];
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, incidents.filter((i) => i.severity === s).length]));
  const visible = filter ? incidents.filter((i) => i.severity === filter) : incidents;
  const x = incidents.find((i) => i.id === selId);
  const slmReady = slm?.online && slm?.modelInstalled;

  return (
    <>
      <header>
        <div>
          <h1>Offline Incident Triage Assistant</h1>
          <p>Rules find and score incidents · a local SLM explains them · every claim links to log evidence</p>
        </div>
        <div className="row">
          <span className={"chip " + (slmReady ? "on" : "")}>
            <i />{slm == null ? "Checking local SLM…" : slm.online ? `${slm.model} ${slm.modelInstalled ? "ready" : "not installed"}` : "SLM offline, rules still work"}
          </span>
          <button onClick={refreshSlm}>Recheck</button>
        </div>
      </header>

      <div className="wrap">
        <aside>
          <section className="box">
            <h3>1. Load logs</h3>
            <label>Try a sample
              <select disabled={busy} value="" onChange={(e) => loadSample(e.target.value)}>
                <option value="">Choose a scenario…</option>
                {sampleSets.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
            </label>
            <label>Or upload your own (CSV / JSON, several at once)
              <input disabled={busy} type="file" multiple accept=".csv,.json" onChange={onUpload} />
            </label>
            <p className="mut">Up to 20 files / 20 MB. Auth and endpoint files can be analysed together. Times are shown in UTC.</p>
            {source?.files?.map((f) => <div className="mut" key={f.filename}>{f.filename}</div>)}
            <label>Saved analyses
              <select disabled={busy} value="" onChange={(e) => restore(e.target.value)}>
                <option value="">Open a previous run…</option>
                {saved.map((h) => <option key={h.analysisId} value={h.analysisId}>{h.created} · {h.events} events · {h.incidents} incidents</option>)}
              </select>
            </label>
          </section>

          <details className="box">
            <summary><h3>2. Detection policy</h3></summary>
            {POLICY.map(([key, label]) => (
              <label key={key}>{label}
                <input disabled={busy} type="number" step={key === "tz_offset" ? "0.25" : "1"} value={cfg[key]} onChange={setNum(key)} />
              </label>
            ))}
            <label className="check">
              <input disabled={busy} type="checkbox" checked={cfg.case_insensitive_users} onChange={(e) => setCfg({ ...cfg, case_insensitive_users: e.target.checked })} />
              Case-insensitive usernames (only if your sources allow it)
            </label>
            <div className="row">
              <button onClick={() => setCfg(DEFAULTS)}>Reset</button>
            </div>
          </details>
          <button className="p wide" disabled={busy || !source} onClick={() => run()}>{busy ? "Working…" : "Run triage"}</button>
        </aside>

        <main>
          {msg && <div role="alert" className="box warn">{msg}</div>}

          {!data && (
            <div className="box empty">
              <h2>Start with a sample or your own logs</h2>
              <p className="mut">Pick “Auth logs” on the left to see a brute-force, privilege-escalation and off-hours scenario triaged by severity.</p>
            </div>
          )}

          {data && (
            <>
              <div className="stats">
                <div className="stat"><b>{data.events}</b><span>events{data.skipped ? ` (${data.skipped} skipped)` : ""}</span></div>
                {SEVERITIES.map((s) => (
                  <button key={s} className={`stat sev ${s} ${filter === s ? "sel" : ""}`} aria-pressed={filter === s} onClick={() => setFilter(filter === s ? null : s)}>
                    <b>{counts[s]}</b><span>{s}</span>
                  </button>
                ))}
              </div>
              <p className="mut">
                {data.sources.map((s) => `${s.id} ${s.filename} (${s.accepted} ok)`).join(" · ")} · analysed in {data.metrics.analysis_ms} ms
                {filter && <> · showing {filter} only (click the card again to clear)</>}
              </p>
              {data.warnings.map((w, i) => <p className="warn" key={i}>{w}</p>)}

              <h2>Incidents by priority</h2>
              {incidents.length === 0 && <p>No indicators matched the current policy. That does not prove the logs are benign.</p>}
              {visible.map((i) => (
                <button key={i.id} className={`inc ${i.severity} ${i.id === selId ? "sel" : ""}`} onClick={() => { setSelId(i.id); setFocus([]); }}>
                  <div className="bar" />
                  <div>
                    <b>INC-{i.id}: {i.users.join(", ")} on {i.devices.join(", ")}</b>
                    <div className="mut">{i.findings.length} findings · {i.evidenceIds.length} evidence records {i.explanation && "· explained"}</div>
                    <div><RuleChips rules={i.rules} /></div>
                  </div>
                  <span className="tag">{i.severity} {i.score}</span>
                </button>
              ))}
            </>
          )}

          {x && (
            <section className={"box detail " + x.severity}>
              <div className="head">
                <h2>INC-{x.id} <span className="tag">{x.severity} {x.score}</span></h2>
                <div className="row">
                  <button className="p" disabled={explaining !== null} onClick={() => explain(x)}>
                    {explaining === x.id ? "Explaining… can take a minute" : x.explanation ? "Explain again" : "Explain with local SLM"}
                  </button>
                  <button onClick={() => report(x, "md", true)}>Copy report</button>
                  <button onClick={() => report(x, "md")}>.md</button>
                  <button onClick={() => report(x, "json")}>.json</button>
                </div>
              </div>
              <p className="mut">{x.scoreExplanation}</p>

              <h3>What was detected</h3>
              <div className="tl">
                {x.findings.map((f, i) => (
                  <div key={i}>
                    <b>{fmt(f.time)}</b> {f.title}
                    <div><RuleChips rules={[f.rule]} /> <Cites ids={f.evidence} focus={focus} onPick={setFocus} /></div>
                  </div>
                ))}
              </div>
              <p className="mut">Indicators require investigation; compromise is not established by these rules alone.</p>

              <h3>Local SLM interpretation</h3>
              <Explanation x={x} focus={focus} onPick={setFocus} />
              {x.explanation && (
                <p className="mut">
                  {x.explanation.model} · {x.explanation.metrics?.wall_ms} ms. {x.explanation.validation}
                </p>
              )}

              <h3>Recommended investigation and conditional response</h3>
              <ul>{x.actions.map((a) => <li key={a}>{a}</li>)}</ul>

              <h3>Supporting evidence {focus.length > 0 && <button className="link" onClick={() => setFocus([])}>clear highlight</button>}</h3>
              <div className="scroll" ref={evidenceRef}>
                <table>
                  <thead><tr>{["ID", "Source", "Time (UTC)", "User", "Device", "IP", "Event", "Detail"].map((h) => <th key={h}>{h}</th>)}</tr></thead>
                  <tbody>
                    {x.rows.map((r) => (
                      <tr key={r.id} className={focus.includes(r.id) ? "focus" : "hit"}>
                        <td>{r.id}</td><td>{r.source} #{r.source_record}</td><td>{fmt(r.time)}</td><td>{r.user}</td><td>{r.device}</td><td>{r.ip}</td><td>{r.event}</td><td>{r.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="mut">A priority score is a policy ranking, not the probability of compromise. Reports contain sensitive data.</p>
            </section>
          )}
        </main>
      </div>
      {toast && <div className="toast" role="status">{toast}</div>}
    </>
  );
}
