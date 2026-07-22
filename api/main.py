"""
FastAPI server that runs the BGP monitor as a background task and serves a
live dashboard.

WHY monitor-inside-the-API (one process):
    The monitor is already asyncio-based and FastAPI runs on an asyncio loop,
    so the monitor can run as a background task alongside HTTP handlers,
    sharing the ALERTS store in memory. No database or queue needed for v1.

Run with:  uvicorn api.main:app --reload
Then open: http://127.0.0.1:8000
"""
import asyncio
import importlib

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from detect.alerts import get_alerts
from config.watched_prefixes import WATCHED_PREFIXES
import ingest.live as live

app = FastAPI(title="BGP Hijack Monitor")


@app.on_event("startup")
async def start_monitor():
    """
    Start the live monitor as a background task when the server boots.

    WHY create_task (not await): stream_forever() loops forever; awaiting it
    would block startup and the HTTP server would never come up.
    """
    asyncio.create_task(live.stream_forever())


@app.get("/api/alerts")
async def api_alerts():
    """Newest-first alerts as JSON — what the dashboard polls."""
    return {"alerts": get_alerts()}


@app.get("/api/status")
async def api_status():
    """Health/config info so the UI can show what's being watched."""
    return {
        "watching": list(WATCHED_PREFIXES.keys()),
        "alert_count": len(get_alerts()),
    }


@app.post("/api/demo")
async def api_demo():
    """
    Replay the documented historical hijacks into the live alert feed.

    WHY a demo endpoint exists:
        A hijack detector's normal state is SILENCE — real hijacks on major
        prefixes are rare, which makes the tool impossible to demonstrate (or
        record a demo GIF of) by waiting. Security tools ship replay modes for
        exactly this reason.

        This reuses the SAME scenarios and SAME check_announcement path as
        eval/replay.py, so what appears on the dashboard is genuine detector
        output, not fabricated UI data.
    """
    scenarios = [
        "eval.scenario_youtube_2008",
        "eval.scenario_amazon_2018",
        "eval.scenario_klayswap_2022",
    ]
    collectors = ["rrc00", "rrc01", "rrc03", "rrc10", "rrc12"]

    # Snapshot the real watched set so live monitoring resumes afterwards.
    original = dict(WATCHED_PREFIXES)
    fired = 0

    for path in scenarios:
        mod = importlib.import_module(path)
        live.load_watched(mod.SCENARIO_WATCHED)
        for _t, prefix, origin in mod.SCENARIO_UPDATES:
            for collector in collectors:
                if live.check_announcement(prefix, origin, collector):
                    fired += 1

    live.load_watched(original)
    return {"replayed": len(scenarios), "alerts_generated": fired}


DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>BGP Hijack Monitor</title>
  <style>
    body { font-family: ui-monospace, Menlo, Consolas, monospace;
           background:#0f1117; color:#e6e6e6; margin:0; padding:24px; }
    h1 { font-size:20px; margin:0 0 4px; }
    .sub { color:#8b93a7; font-size:13px; margin-bottom:20px; }
    .watch { background:#171a23; padding:10px 14px; border-radius:8px;
             font-size:13px; margin-bottom:16px; }
    button { background:#2d6cdf; color:#fff; border:0; padding:10px 16px;
             border-radius:6px; font-family:inherit; font-size:13px;
             cursor:pointer; margin-bottom:18px; }
    button:hover { background:#3f7ae8; }
    .alert { background:#171a23; border-left:4px solid #e5534b;
             padding:12px 14px; border-radius:6px; margin-bottom:10px; }
    .alert.mid { border-left-color:#d29922; }
    .row { display:flex; justify-content:space-between; align-items:center; }
    .kind { font-weight:700; color:#e5534b; }
    .kind.mid { color:#d29922; }
    .score { font-size:18px; font-weight:700; }
    .meta { color:#8b93a7; font-size:12px; margin-top:6px; }
    .empty { color:#8b93a7; font-size:14px; padding:20px 0; }
  </style>
</head>
<body>
  <h1>BGP Hijack Monitor</h1>
  <div class="sub">Live RIPE RIS feed &middot; trie matching &middot; confidence scoring</div>
  <div class="watch" id="watch">loading...</div>
  <button onclick="runDemo()">Replay historical hijacks (2008 / 2018 / 2022)</button>
  <div id="alerts"><div class="empty">No alerts yet - monitoring...</div></div>

<script>
async function runDemo() {
  await fetch('/api/demo', { method: 'POST' });
  refresh();
}

async function refresh() {
  try {
    const s = await (await fetch('/api/status')).json();
    document.getElementById('watch').textContent =
      'Watching ' + s.watching.length + ' prefixes: ' + s.watching.join(', ');

    const d = await (await fetch('/api/alerts')).json();
    const box = document.getElementById('alerts');

    if (!d.alerts.length) {
      box.innerHTML = '<div class="empty">No alerts yet - monitoring...</div>';
      return;
    }

    box.innerHTML = d.alerts.map(function(a) {
      var mid = a.score < 80 ? ' mid' : '';
      return '<div class="alert' + mid + '">'
        + '<div class="row"><span class="kind' + mid + '">' + a.kind + '</span>'
        + '<span class="score">' + a.score + '</span></div>'
        + '<div>' + a.prefix + ' announced by AS' + a.origin + '</div>'
        + '<div class="meta">inside ' + a.watched_prefix + ' &middot; ' + a.time
        + (a.collector ? ' &middot; ' + a.collector : '') + '</div>'
        + '<div class="meta">' + a.reasons.join(' &middot; ') + '</div>'
        + '</div>';
    }).join('');
  } catch (e) {
    console.error(e);
  }
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Single-page dashboard: no build step, polls /api/alerts every 2s."""
    return DASHBOARD_HTML
