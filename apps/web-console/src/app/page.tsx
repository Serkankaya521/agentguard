import Link from 'next/link';
export default function Home(){return <><div className="eyebrow">Autonomous agent security</div><h1>Continuously challenge every agent you deploy.</h1><p className="lede">Evolve adversarial campaigns, verify target-side evidence, turn confirmed failures into findings and replay every fix as a regression.</p><div className="statusbar"><span><b>RUNTIME</b> enforced</span><span><b>RED TEAM</b> bounded</span><span><b>EVIDENCE</b> tenant-scoped</span><span><b>LEARNING</b> governed</span></div><div className="grid">
  <Link className="card featured" href="/campaigns"><div className="metric">01</div><h2>Campaign operations</h2><p className="muted">Create, schedule, pause and execute response-aware mutation campaigns.</p></Link>
  <Link className="card" href="/findings"><div className="metric">02</div><h2>Evidence-backed findings</h2><p className="muted">Track confirmed canary disclosures through remediation and retest.</p></Link>
  <Link className="card" href="/policies"><div className="metric">03</div><h2>Runtime defense</h2><p className="muted">Publish signed policies and enforce decisions without blocking intelligence work.</p></Link>
</div></>}
