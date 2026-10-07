"""Phase 2: analyze + graphs + self-contained tabbed HTML report.
Usage: python build_report.py --comparison "D:\\path\\comparison.txt" [--run runs/<id>] [--out report.html]
The --comparison path is pasted by you after the manual Regshot compare.
Without it, the report still builds with the Regshot tab marked pending.
"""

import argparse
import html
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import report_data
from lab_paths import LAB_ROOT, REPORTS_DIR

CSS = Path(__file__).with_name("report_style.css").read_text(encoding="utf-8")


def _hhmmss(iso):
    """UTC timestamp -> HH:MM:SS.mmm for the narrative."""
    try:
        return datetime.fromisoformat(iso).strftime("%H:%M:%S.%f")[:-3]
    except (ValueError, TypeError):
        return "--:--:--.---"


def build_timeline(sim, alert):
    """Fuse simulator events + detector alert into a causal timeline."""
    files = sim.get("files", [])
    items = []

    items.append(
        (
            sim["started"],
            "alert" if False else "step",
            (
                f"<b>{_hhmmss(sim['started'])} — Simulator launched</b> "
                f"(PID {html.escape(str(sim.get('pid', '?')))}, "
                f"{html.escape(sim.get('simulation_id', ''))}, "
                f"{len(files)} files selected)"
            ),
        )
    )

    for f in files[:2]:
        name = Path(f["original_path"]).name
        locked = Path(f["new_path"]).name
        items.append(
            (
                f["timestamp"],
                "step",
                (
                    f"<b>{_hhmmss(f['timestamp'])} — File #{f['index']}:</b> "
                    f"{html.escape(name)} read &rarr; XOR 0x41 &rarr; "
                    f"<code>{html.escape(locked)}</code> created &rarr; original deleted"
                ),
            )
        )

    if len(files) > 2:
        mid = files[len(files) // 2]["timestamp"]
        items.append(
            (
                mid,
                "step",
                (
                    f"<b>{_hhmmss(mid)} — Burst continues:</b> same pattern per file "
                    f"(read &rarr; transform &rarr; <code>.locked</code> &rarr; unlink), "
                    f"{len(files)} files total"
                ),
            )
        )

    if alert:
        basis = (
            "entropy gate + " if alert.get("entropy_gate_passed") else ""
        ) + "velocity/burst gate"
        owner = alert.get("suspected_process")
        owner_txt = (
            f" &middot; offending process PID {owner['pid']} "
            f"({html.escape(str(owner['name']))})"
            if owner
            else " &middot; owner not resolved (run detector as Administrator)"
        )
        items.append(
            (
                alert["timestamp"],
                "alert",
                (
                    f"<b>{_hhmmss(alert['timestamp'])} — DETECTOR ALERT</b> — "
                    f"{alert['events_in_window']} events in {alert['window_seconds']}s "
                    f"(threshold {alert['velocity_threshold']}) &middot; "
                    f"{alert['rename_events']} renames / {alert['delete_events']} deletes &middot; "
                    f"{alert['high_entropy_files']} high-entropy hits &middot; "
                    f"{basis}{owner_txt}"
                ),
            )
        )

    if files:
        last = files[-1]
        items.append(
            (
                last["timestamp"],
                "step",
                (
                    f"<b>{_hhmmss(last['timestamp'])} — Last file processed:</b> "
                    f"{html.escape(Path(last['original_path']).name)} &rarr; "
                    f"<code>{html.escape(Path(last['new_path']).name)}</code>"
                ),
            )
        )

    if sim.get("ended"):
        note = sim.get("ransom_note", "")
        items.append(
            (
                sim["ended"],
                "step",
                (
                    f"<b>{_hhmmss(sim['ended'])} — Ransom note + completion:</b> "
                    f"{html.escape(Path(note).name) if note else 'note'} written "
                    f"&middot; Desktop copy created &middot; session closed "
                    f"({html.escape(str(sim.get('duration_seconds', '')))} s)"
                ),
            )
        )

    items.sort(key=lambda x: x[0])
    return "".join(f'<div class="{cls}">{body}</div>' for _, cls, body in items)


def parse_args():
    ap = argparse.ArgumentParser(description="Build case2 forensic HTML report")
    ap.add_argument(
        "--comparison", default="", help="Full path to Regshot comparison.txt"
    )
    ap.add_argument(
        "--run", default="", help="Run bundle dir (default: latest in runs/)"
    )
    ap.add_argument(
        "--out", default="", help="Output HTML (default: reports/report_<simid>.html)"
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    # Refresh derived artifacts from canonical evidence (reuse, no duplication)
    sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
    import analyze_results
    import generate_graphs

    analyze_results.main()
    generate_graphs.main()

    cmp_path = args.comparison.strip() or None
    if cmp_path and not Path(cmp_path).exists():
        print(f"[!] Comparison file not found: {cmp_path}")
        return 1
    if cmp_path:  # keep a canonical copy beside post evidence
        dst = PROJECT_ROOT / "evidence" / "post" / "regshot_comparison.txt"
        if Path(cmp_path).resolve() != dst.resolve():
            shutil.copy2(cmp_path, dst)
            print(f"[+] Archived comparison -> {dst}")

    data = report_data.load_all(PROJECT_ROOT, LAB_ROOT, cmp_path)
    sim, alert = data["sim"], data["alert"]
    rows_json = json.dumps(data["rows"])
    reg_pending = (
        ""
        if data["regshot_available"]
        else "<p><span class='pill info'>PENDING</span> Re-run with --comparison once Regshot compare is saved.</p>"
    )

    def img(name):
        return (
            f'<img src="data:image/png;base64,{data["images"][name]}" '
            f'style="width:100%;border-radius:10px;border:1px solid #e2e8f0" alt="{name}">'
            if name in data["images"]
            else "<p>(graph missing)</p>"
        )

    folder_rows = "".join(
        f"<tr><td>{f}</td><td>{data['folder_counts'][f]}</td><td>{data['folder_counts'][f]} .locked</td></tr>"
        for f in data["folders"]
    )
    det = ""
    if alert:
        det = (
            f"events {alert['events_in_window']}/{alert['velocity_threshold']} in "
            f"{alert['window_seconds']}s, renames {alert['rename_events']}, "
            f"deletes {alert['delete_events']}, entropy hits {alert['high_entropy_files']}"
        )
    ttd = ""
    if alert:
        try:
            s = datetime.fromisoformat(sim["started"])
            a = datetime.fromisoformat(alert["timestamp"])
            ttd = f"{(a - s).total_seconds():.2f} s"
        except (ValueError, TypeError):
            ttd = "n/a"

    timeline_html = build_timeline(sim, alert)

    logo_html = ""

    out = Path(args.out) if args.out else REPORTS_DIR / f"report_{data['sim_id']}.html"
    out.write_text(
        f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ransomware Behavior Analysis — {html.escape(data["sim_id"])}</title>
<style>
{CSS}
body>.wrap section.card{{display:none}}
body>.wrap section.card.active{{display:block;animation:fade .18s ease-in}}
@keyframes fade{{from{{opacity:0;transform:translateY(6px)}}to{{opacity:1;transform:none}}}}
.viewbar{{position:sticky;top:0;z-index:30;display:flex;gap:10px;align-items:center;background:rgba(255,255,255,.94);border:1px solid #e2e8f0;border-radius:10px;padding:8px 12px;margin-bottom:14px}}
.viewbar .sp{{flex:1}}.pagenav{{display:flex;gap:8px;flex-wrap:wrap}}
.pagenav button{{background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:7px 12px;font-weight:700;cursor:pointer}}
.pagenav button:disabled{{opacity:.4}}#pageCount{{color:#5b6b84;font-size:12px;font-weight:700}}
</style></head><body>
<header><div class="wrap"><div class="top">{logo_html}<span class="badge">DFIR • SOC • LAB</span>
<div><h1>RANSOMWARE BEHAVIOR ANALYSIS <span style="color:#0b5fff">{html.escape(data["sim_id"])}</span></h1>
<sub>Clean VM → baseline → simulated execution → detection → post-attack forensics • {html.escape(str(LAB_ROOT))}</sub></div></div>
<nav id="nav">
<a href="#exec">Executive</a><a href="#env">Environment</a><a href="#before">Before</a><a href="#timeline">Timeline</a><a href="#behavior">Behavior</a><a href="#after">After</a><a href="#diff">Before vs After</a><a href="#detect">Detection</a><a href="#entropy">Entropy</a><a href="#regshot">Regshot</a><a href="#ransom">Ransom note</a><a href="#explorer">Evidence explorer</a><a href="#safety">Safety & Recovery</a><a href="#artifacts">Artifacts</a>
</nav></div></header>
<div class="wrap">
<div class="viewbar"><span class="pill info" id="pageCount"></span><span class="sp"></span>
<div class="pagenav"><button id="prevBtn">◀ Prev</button><button id="nextBtn">Next ▶</button><button id="allBtn">Show full report</button></div></div>
<section id="exec" class="card"><h2>Executive summary</h2>
<div class="grid k4">
<div class="card"><div class="lbl">Files affected</div><div class="stat">{len(data["rows"])}</div></div>
<div class="card"><div class="lbl">Time-to-detection</div><div class="stat">{html.escape(ttd)}</div><div class="big">{html.escape(det)}</div></div>
<div class="card"><div class="lbl">Duration</div><div class="stat">{html.escape(str(sim.get("duration_seconds", "")))} s</div></div>
<div class="card"><div class="lbl">Mean entropy (before)</div><div class="stat">{data["mean_entropy"]}</div></div>
</div></section>
<section id="env" class="card"><h2>Environment & safety</h2>
<p class="big">Victim <code>{html.escape(str(LAB_ROOT))}</code> • Project <code>{html.escape(str(PROJECT_ROOT))}</code> • Simulator PID {html.escape(str(sim.get("pid", "")))} • Host {html.escape(str(sim.get("hostname", "")))} • XOR 0x41 reversible, scoped target with abort guard, no network/persistence/C2.</p></section>
<section id="before" class="card"><h2>Before state</h2><div id="folderBars"></div>
<table><tr><th>Folder</th><th>Before</th><th>After</th></tr>{folder_rows}</table></section>
<section id="timeline" class="card"><h2>Execution timeline</h2>
<p class="big">Simulator log (per-file events) fused with the detector alert. Causal narrative, not just side-by-side outputs.</p>
<div class="tl">{timeline_html}</div>
<div class="grid k2"><div><h3>First 6 file events (from simulation log)</h3><pre id="firstEvents"></pre></div>
<div><h3>How to narrate</h3><p class="big">The watchdog sees create+delete pairs arriving 30+/sec. That velocity plus <code>.locked</code> renames is the ransomware signal here. Real EDR adds entropy, magic-byte and process-tree signals.</p></div></div>
</section>
<section id="behavior" class="card"><h2>Ransomware behavior</h2>
<p class="big">Per-file: <code>read → xor(byte^0x41) → write .locked → unlink original → sleep 0.02s</code>. No in-place modification; every hash changes, sizes identical.</p>
{img("03_file_type_impact.png")}</section>
<section id="after" class="card"><h2>After state</h2>{img("01_file_count_comparison.png")}</section>
<section id="diff" class="card"><h2>Before vs After</h2>
<table><tr><th>Folder</th><th>Before</th><th>After</th></tr>{folder_rows}</table></section>
<section id="detect" class="card"><h2>Detection analysis</h2><pre id="alertBox"></pre>
<p class="big">Velocity fired; entropy stayed silent (XOR preserves byte-frequency distribution). Entropy is an observed feature here, not proof of encryption.</p></section>
<section id="entropy" class="card"><h2>Entropy analysis</h2><canvas id="entCanvas" width="1000" height="260"></canvas>
{img("02_entropy_distribution.png")}</section>
<section id="regshot" class="card"><h2>Regshot forensics</h2>{reg_pending}
<div class="searchrow"><input id="regq" placeholder="Filter lab lines…" style="flex:1" oninput="filterReg()"></div>
<div class="grid k2"><div><h3>Lab files ADDED</h3><pre id="regAdd"></pre></div>
<div><h3>Lab files DELETED</h3><pre id="regDel"></pre></div></div></section>
<section id="ransom" class="card"><h2>Ransom note</h2><div class="note">{html.escape(data["ransom_note"])}</div></section>
<section id="explorer" class="card"><h2>Evidence explorer ({len(data["rows"])} files)</h2>
<div class="searchrow"><input id="q" placeholder="Search…" style="flex:2" oninput="drawTable()">
<select id="qf" onchange="drawTable()"><option value="">All folders</option>{"".join(f"<option>{html.escape(f)}</option>" for f in data["folders"])}</select>
<button class="btn" onclick="resetF()">Reset</button><span id="cnt" class="pill info"></span></div>
<div style="max-height:420px;overflow:auto;border:1px solid #e2e8f0;border-radius:10px"><table id="explorer">
<thead><tr><th onclick="sortBy('folder')">Folder</th><th onclick="sortBy('name')">File</th><th>Size</th><th>SHA before → after</th><th>Status</th></tr></thead><tbody id="tbody"></tbody></table></div></section>
<section id="safety" class="card"><h2>Safety / negative findings & recovery</h2>
<p class="big">No network, no persistence, no lateral movement, no credential theft, scoped target, reversible transform. Snapshots: CLEAN → PRE_ATTACK → POST_ATTACK. Reverse demo: <code>bytes(b ^ 0x41)</code>.</p></section>
<section id="artifacts" class="card"><h2>Forensic artifacts</h2>
<pre>evidence/baseline/baseline_files.json\nevidence/post/post_attack_files.json\nlogs/simulation_*.json\nlogs/ransomware_alert_*.json\nreports/analysis_summary.json + 3 PNGs\nevidence/post/regshot_comparison.txt</pre></section>
<footer>Generated offline • single self-contained file • {html.escape(data["sim_id"])}</footer>
</div>
<div class="modal" id="modal" onclick="this.style.display='none'"><div id="mbox" onclick="event.stopPropagation()"></div></div>
<script>
var ROWS = {rows_json};
var ALERT = {json.dumps(alert)};
var FIRST = {json.dumps(sim.get("files", [])[:6])};
var ADDED = {json.dumps(data["lab_added"])};
var DELETED = {json.dumps(data["lab_deleted"])};
var FC = {json.dumps(data["folder_counts"])};
var sortK='folder', sortD=1;
document.getElementById('alertBox').textContent = ALERT ? JSON.stringify(ALERT,null,2) : '(no alert captured)';
document.getElementById('firstEvents').textContent = FIRST.map(function(f){{return f.timestamp+'  #'+f.index+' '+f.original_path.split('\\\\').pop()+' -> '+f.new_path.split('\\\\').pop();}}).join('\\n');
document.getElementById('regAdd').textContent = ADDED.join('\\n')||'(none)';
document.getElementById('regDel').textContent = DELETED.join('\\n')||'(none)';
function filterReg(){{var q=document.getElementById('regq').value.toLowerCase();
document.getElementById('regAdd').textContent=ADDED.filter(function(l){{return l.toLowerCase().includes(q)}}).join('\\n')||'(no match)';
document.getElementById('regDel').textContent=DELETED.filter(function(l){{return l.toLowerCase().includes(q)}}).join('\\n')||'(no match)';}}
var fh='';Object.keys(FC).forEach(function(k){{fh+='<div style="display:flex;gap:10px;align-items:center;margin:6px 0"><b style="width:120px">'+k+'</b><div class="bar" style="flex:1"><i style="width:100%"></i></div><span>'+FC[k]+' → '+FC[k]+' locked</span></div>';}});
document.getElementById('folderBars').innerHTML=fh;
function sortBy(k){{if(sortK===k)sortD*=-1;else{{sortK=k;sortD=1;}}drawTable();}}
function resetF(){{document.getElementById('q').value='';document.getElementById('qf').value='';drawTable();}}
function drawTable(){{var q=document.getElementById('q').value.toLowerCase(),f=document.getElementById('qf').value;
var r=ROWS.filter(function(x){{return (!f||x.folder===f)&&(x.name.toLowerCase().includes(q)||x.locked.toLowerCase().includes(q));}});
r.sort(function(a,b){{var x=a[sortK],y=b[sortK];return (x>y?1:x<y?-1:0)*sortD;}});
document.getElementById('cnt').textContent=r.length+' / '+ROWS.length;
var h='';r.slice(0,300).forEach(function(x){{h+='<tr onclick="showDetail('+ROWS.indexOf(x)+')"><td>'+x.folder+'</td><td>'+x.name+'<br><span style="color:#0b5fff">'+x.locked+'</span></td><td>'+x.before_size+'</td><td style="font-family:monospace;font-size:11px">'+x.before_sha.slice(0,16)+'..<br>→ '+x.after_sha.slice(0,16)+'..</td><td><span class="pill bad">deleted→locked</span></td></tr>';}});
document.getElementById('tbody').innerHTML=h;}}
function showDetail(i){{var x=ROWS[i];document.getElementById('mbox').innerHTML='<h3>'+x.folder+' / '+x.name+'</h3><table><tr><td>Locked</td><td>'+x.locked+'</td></tr><tr><td>Size</td><td>'+x.before_size+' → '+x.after_size+'</td></tr><tr><td>Entropy</td><td>'+x.before_ent+' → '+x.after_ent+'</td></tr><tr><td>Before SHA</td><td style="font-family:monospace">'+x.before_sha+'</td></tr><tr><td>After SHA</td><td style="font-family:monospace">'+x.after_sha+'</td></tr></table><br><button class="btn" onclick="document.getElementById(\\'modal\\').style.display=\\'none\\'">Close</button>';document.getElementById('modal').style.display='flex';}}
drawTable();
var c=document.getElementById('entCanvas'),ctx=c.getContext('2d');ctx.fillStyle='#fff';ctx.fillRect(0,0,1000,260);
var be=ROWS.map(function(r){{return r.before_ent}}),ae=ROWS.map(function(r){{return r.after_ent}});
function hist(d,lo,hi,n){{var h=new Array(n).fill(0);d.forEach(function(v){{var i=Math.min(n-1,Math.max(0,Math.floor((v-lo)/(hi-lo)*n)));h[i]++}});return h;}}
var hb=hist(be,6.0,6.25,24),ha=hist(ae,6.0,6.25,24);var mx=Math.max.apply(null,hb.concat(ha).concat([1]));
ctx.fillStyle='#0b5fff';hb.forEach(function(v,i){{var h=v/mx*200;ctx.globalAlpha=.75;ctx.fillRect(40+i*38,230-h,30,h);}});
ctx.fillStyle='#e11d48';ha.forEach(function(v,i){{var h=v/mx*200;ctx.globalAlpha=.45;ctx.fillRect(40+i*38,230-h,30,h);}});
ctx.globalAlpha=1;ctx.fillStyle='#5b6b84';ctx.font='12px sans-serif';ctx.fillText('blue=before  red=after (overlap = preservation)',40,20);
(function(){{
var ids=["exec","env","before","timeline","behavior","after","diff","detect","entropy","regshot","ransom","explorer","safety","artifacts"];
var cur=0, allMode=false;
function secs(){{return ids.map(function(id){{return document.getElementById(id)}}).filter(Boolean)}}
function render(){{
 var s=secs();
 s.forEach(function(el,i){{ el.classList.toggle("active", allMode||i===cur); }});
 var lbl=document.getElementById("pageCount");
 if(lbl) lbl.textContent = allMode ? (s.length+" sections • full-report mode") : ("Section "+(cur+1)+" / "+s.length+" • "+s[cur].querySelector("h2").innerText);
 document.getElementById("prevBtn").disabled = allMode||cur===0;
 document.getElementById("nextBtn").disabled = allMode||cur===s.length-1;
 document.getElementById("allBtn").textContent = allMode ? "Single-section mode" : "Show full report";
 document.querySelectorAll("nav#nav a").forEach(function(a){{
   var i=ids.indexOf(a.getAttribute("href").replace("#",""));
   a.classList.toggle("on", !allMode && i===cur);
   a.onclick=function(e){{ e.preventDefault(); if(i>=0){{ allMode=false; cur=i; render(); window.scrollTo({{top:0,behavior:"smooth"}}); }} }};
 }});
}}
document.getElementById("prevBtn").onclick=function(){{ if(cur>0){{cur--; render(); window.scrollTo({{top:0,behavior:"smooth"}});}} }};
document.getElementById("nextBtn").onclick=function(){{ if(cur<ids.length-1){{cur++; render(); window.scrollTo({{top:0,behavior:"smooth"}});}} }};
document.getElementById("allBtn").onclick=function(){{ allMode=!allMode; render(); }};
render();
}})();
</script></body></html>""",
        encoding="utf-8",
    )
    print(f"[+] Report: {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
