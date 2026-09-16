"""Visual system for the local AgentGuard security operations console."""

CSS = r"""
<style>
:root {
  --ag-bg: #070a0d;
  --ag-panel: #0d1217;
  --ag-panel-2: #111820;
  --ag-line: #25303a;
  --ag-text: #e7edf2;
  --ag-muted: #8593a0;
  --ag-cyan: #48d7df;
  --ag-green: #78e08f;
  --ag-red: #ff6b6b;
  --ag-amber: #f0bd56;
}
.stApp { background: var(--ag-bg); color: var(--ag-text); }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stSidebar"] { background: #090e13; border-right: 1px solid var(--ag-line); }
.block-container { max-width: 1480px; padding-top: 1.8rem; padding-bottom: 4rem; }
h1,h2,h3 { font-family: Inter, ui-sans-serif, system-ui, sans-serif; letter-spacing: -.025em; }
h1 { font-size: 2.2rem !important; font-weight: 660 !important; }
p,li,label,[data-testid="stMetricLabel"] { font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
.ag-kicker { color: var(--ag-cyan); font: 700 11px/1.2 ui-monospace, monospace; letter-spacing: .16em; text-transform: uppercase; }
.ag-hero { display:flex; justify-content:space-between; gap:24px; align-items:flex-end; border-bottom:1px solid var(--ag-line); padding: 10px 0 22px; margin-bottom:22px; }
.ag-hero h1 { margin:.45rem 0 .5rem; }
.ag-sub { color:var(--ag-muted); max-width:850px; font-size:15px; }
.ag-status { display:inline-flex; align-items:center; gap:8px; border:1px solid #2d4942; background:#0d1a17; color:var(--ag-green); padding:7px 11px; font:700 11px ui-monospace,monospace; text-transform:uppercase; }
.ag-dot { width:7px; height:7px; background:var(--ag-green); border-radius:50%; }
.ag-strip { display:grid; grid-template-columns:repeat(4,1fr); border:1px solid var(--ag-line); background:var(--ag-panel); margin:18px 0 28px; }
.ag-stat { padding:17px 19px; border-right:1px solid var(--ag-line); }
.ag-stat:last-child { border-right:0; }
.ag-stat span { display:block; color:var(--ag-muted); font:650 10px ui-monospace,monospace; letter-spacing:.1em; text-transform:uppercase; }
.ag-stat strong { display:block; margin-top:8px; font:650 23px Inter,system-ui; }
.ag-panel { border:1px solid var(--ag-line); background:var(--ag-panel); padding:20px; }
.ag-panel-title { color:var(--ag-text); font:650 15px Inter,system-ui; margin-bottom:5px; }
.ag-note { color:var(--ag-muted); font-size:13px; }
.ag-severity-high { color:var(--ag-red); font-weight:700; }
.ag-severity-low { color:var(--ag-green); font-weight:700; }
.ag-mono { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
div[data-testid="stMetric"] { background:var(--ag-panel); border:1px solid var(--ag-line); padding:14px 16px; }
div[data-testid="stMetricValue"] { font-family:ui-monospace,SFMono-Regular,monospace; color:var(--ag-text); }
div[data-baseweb="tab-list"] { gap:20px; border-bottom:1px solid var(--ag-line); }
button[data-baseweb="tab"] { background:transparent; padding-left:0; padding-right:0; }
.stButton > button { border-radius:2px; border:1px solid var(--ag-cyan); background:var(--ag-cyan); color:#031012; font-weight:800; }
.stButton > button:hover { border-color:#8cf8ff; background:#8cf8ff; color:#031012; }
.stTextInput input,.stTextArea textarea,.stSelectbox div[data-baseweb="select"] > div { border-radius:2px !important; }
@media (max-width: 800px) { .ag-strip{grid-template-columns:1fr 1fr}.ag-stat:nth-child(2){border-right:0}.ag-hero{display:block}.ag-status{margin-top:14px} }
</style>
"""
