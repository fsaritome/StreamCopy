"""Benchmark charts for the README (docs/img/chart-*.svg), from the measured numbers in BENCHMARKS.md.

    python -I tools/charts.py

Plain SVG, standard library only. Horizontal bars anchored at zero (time: shorter is better), one shared scale per
chart, values written next to every bar, a legend for two series. Colors: the validated reference palette (slot 1
blue = scopy, slot 2 orange = the tool it is compared with), with its own dark-mode steps; text in text colors.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "img")

STYLE = """
  <style>
    .surface { fill: none; }
    .title { font: 700 19px system-ui, "Segoe UI", Inter, Arial, sans-serif; fill: #0b0b0b; }
    .sub { font: 400 13.5px system-ui, "Segoe UI", Inter, Arial, sans-serif; fill: #52514e; }
    .lab { font: 500 13.5px system-ui, "Segoe UI", Inter, Arial, sans-serif; fill: #0b0b0b; }
    .val { font: 600 12.5px system-ui, "Segoe UI", Inter, Arial, sans-serif; fill: #0b0b0b; }
    .note { font: 400 11.5px system-ui, "Segoe UI", Inter, Arial, sans-serif; fill: #6b6a66; }
    .grid { stroke: #e4e3df; stroke-width: 1; }
    .axis { stroke: #b9b8b2; stroke-width: 1; }
    .s1 { fill: #2a78d6; } .s2 { fill: #eb6834; }
    .ref { stroke: #52514e; stroke-width: 1.5; stroke-dasharray: 5 4; }
    .reflab { font: 600 12px system-ui, "Segoe UI", Inter, Arial, sans-serif; fill: #52514e; }
    @media (prefers-color-scheme: dark) {
      .title, .lab, .val { fill: #f0efec; } .sub { fill: #c3c2b7; } .note { fill: #9e9d96; }
      .grid { stroke: #33332f; } .axis { stroke: #5a5953; }
      .s1 { fill: #3987e5; } .s2 { fill: #d95926; }
      .ref { stroke: #c3c2b7; } .reflab { fill: #c3c2b7; }
    }
  </style>
"""

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def fmt_s(v):
    if v >= 60:
        m, s = divmod(round(v), 60)
        return f"{m}:{s:02d} min"
    return f"{v:.1f} s" if v < 10 else f"{v:.0f} s"

def bar(x, y, w, h, cls, title):
    """A bar anchored at x (the zero line), 4 px rounded data end, a native tooltip."""
    w = max(w, 3)
    r = min(4, w / 2, h / 2)
    d = f"M{x},{y} H{x + w - r} Q{x + w},{y} {x + w},{y + r} V{y + h - r} Q{x + w},{y + h} {x + w - r},{y + h} H{x} Z"
    return f'<path class="{cls}" d="{d}"><title>{esc(title)}</title></path>'

def chart(name, title, sub, groups, series, vmax, ticks, note, fmt=fmt_s, factor=None, label_w=210, ref=None):
    """groups: [(label, [values per series])]; series: [(name, css class)]."""
    W = 780
    left, right = label_w, 120
    plot_w = W - left - right
    bh, gap, ggap = 18, 2, 18
    top = 88 if len(series) > 1 else 70
    n = len(series)
    gh = n * bh + (n - 1) * gap
    H = top + len(groups) * (gh + ggap) + 44
    sx = lambda v: left + v / vmax * plot_w
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t s">',
         f'  <title id="t">{esc(title)}</title><desc id="s">{esc(sub)}</desc>', STYLE,
         f'  <rect class="surface" width="{W}" height="{H}"/>',
         f'  <text class="title" x="16" y="30">{esc(title)}</text>',
         f'  <text class="sub" x="16" y="52">{esc(sub)}</text>']
    if n > 1:
        lx = 16
        for sname, cls in series:
            o.append(f'  <rect class="{cls}" x="{lx}" y="64" width="14" height="14" rx="3"/>')
            o.append(f'  <text class="lab" x="{lx + 20}" y="76">{esc(sname)}</text>')
            lx += 20 + 9 * len(sname) + 28
    plot_top, plot_bot = top - 6, top + len(groups) * (gh + ggap) - ggap + 6
    for t in ticks:
        x = sx(t)
        o.append(f'  <line class="grid" x1="{x:.1f}" y1="{plot_top}" x2="{x:.1f}" y2="{plot_bot}"/>')
        o.append(f'  <text class="note" x="{x:.1f}" y="{plot_bot + 16}" text-anchor="middle">{esc(fmt(t) if t else "0")}</text>')
    o.append(f'  <line class="axis" x1="{left}" y1="{plot_top}" x2="{left}" y2="{plot_bot}"/>')
    if ref:
        rv, rl = ref
        x = sx(rv)
        o.append(f'  <line class="ref" x1="{x:.1f}" y1="{plot_top - 22}" x2="{x:.1f}" y2="{plot_bot}"/>')
        o.append(f'  <text class="reflab" x="{x + 6:.1f}" y="{plot_top - 12}">{esc(rl)}</text>')
    y = top
    for label, vals in groups:
        o.append(f'  <text class="lab" x="{left - 12}" y="{y + gh / 2 + 5:.1f}" text-anchor="end">{esc(label)}</text>')
        for i, ((sname, cls), v) in enumerate(zip(series, vals)):
            by = y + i * (bh + gap)
            if v is None:
                continue
            w = sx(v) - left
            o.append("  " + bar(left, by, w, bh, cls, f"{label} — {sname}: {fmt(v)}"))
            o.append(f'  <text class="val" x="{left + max(w, 3) + 6:.1f}" y="{by + bh / 2 + 4.5:.1f}">{esc(fmt(v))}</text>')
        if factor and len(vals) == 2 and vals[0] and vals[1]:
            f = vals[1] / vals[0]
            o.append(f'  <text class="val" x="{W - 16}" y="{y + gh / 2 + 5:.1f}" text-anchor="end">{f:.0f}× faster</text>')
        y += gh + ggap
    o.append(f'  <text class="note" x="16" y="{H - 10}">{esc(note)}</text>')
    o.append("</svg>")
    with open(os.path.join(OUT, f"chart-{name}.svg"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(o) + "\n")

# 1. A user's laptop and the file server: Explorer vs scopy (BENCHMARKS.md, averages of two runs each).
chart(
    "laptop",
    "A project of 1,975 small files (140 MB): laptop ⇄ file server",
    "Wall-clock time incl. scopy's start-up. Windows Explorer (drag & drop) vs scopy --profile interactive.",
    [
        ("Save, over Wi-Fi", [3.0, 300.0]),
        ("Open, over Wi-Fi", [5.3, 149.5]),
        ("Save, over cable", [2.0, 72.5]),
        ("Open, over cable", [4.3, 48.0]),
    ],
    [("scopy", "s1"), ("Windows Explorer", "s2")],
    320, [0, 60, 120, 180, 240, 300],
    "Averages of two runs each (BENCHMARKS.md). The larger project (16,372 files) was not run with Explorer: ≈ 39 min estimated vs 11 s.",
    factor=True,
)

# 2. Server to server over the network: robocopy vs scopy (BENCHMARKS.md).
chart(
    "robocopy",
    "Many small files over the network: robocopy /MT:32 vs scopy",
    "Same data, same link, fresh destination. Shorter is better.",
    [
        ("496 MB real-world files, 8,585 files", [21.2, 351.9]),
        ("same, scopy without compression", [86.1, None]),
        ("20,003 tiny files, 246 MB", [69.0, 737.8]),
        ("2,000 tiny files, 17 MB", [5.7, 79.7]),
    ],
    [("scopy", "s1"), ("robocopy /MT:32", "s2")],
    780, [0, 120, 240, 360, 480, 600, 720],
    "BENCHMARKS.md (scopy 0.1–0.3), a routed ~40–70 Mbit/s link. Streaming fills the link; zstd 3 then cuts the bytes ≈ 5×.",
    factor=True, label_w=250,
)

# 3. Two-way sync and open-file locks, live over a VPN (BENCHMARKS.md).
chart(
    "sync",
    "Two-way sync over a VPN: until a change is on the other side",
    "Live agent on a laptop, server-side changes made over SMB as another machine would (server checked every 15 s).",
    [
        ("New file on the PC → server", [5.6]),
        ("New file on the server → PC", [6.2]),
        ("Changed on the server → PC", [3.6]),
        ("Deleted on the server → PC", [3.1]),
        ("Deleted on the PC → server", [4.6]),
        ("Conflict resolved (both kept)", [1.9]),
        ("Word opened → locked on the server", [3.3]),
        ("Word closed → lock released", [3.5]),
    ],
    [("seconds", "s1")],
    8, [0, 2, 4, 6, 8],
    "BENCHMARKS.md (scopy 0.17–0.18). Renames and moves travel as moves: nothing is sent again.",
    fmt=lambda v: f"{v:.1f} s" if v else "0", label_w=270,
)
# 4. Through a real 10 Gbit link (BENCHMARKS.md). Both rates from the exact size of the test set and the measured transfer
#    time / wire rate, so they compare directly: data = 20,531,332,281 bytes over the transfer; wire = MiB/s on the wire.
ARCHIVE_BITS = 20_531_332_281 * 8
gbit = lambda secs: ARCHIVE_BITS / secs / 1e9
wire = lambda mib_s: mib_s * 1_048_576 * 8 / 1e9
chart(
    "10gbit",
    "Filling a 10 Gbit link: 19.1 GB, 85,513 files, between two VMs",
    "File data delivered vs bytes on the wire. With compression scopy delivers more data than the link itself could carry.",
    [
        ("Compression off", [gbit(17.8), gbit(17.8)]),
        ("zstd level 1", [gbit(14.6), wire(785)]),
        ("zstd level 3", [gbit(15.9), wire(713)]),
        ("zstd 1, written to disk", [gbit(14.8), wire(774)]),
    ],
    [("file data delivered", "s1"), ("on the wire", "s2")],
    12.5, [0, 2, 4, 6, 8, 10, 12],
    "Two VMs on two hosts, physical 10 Gbit link (BENCHMARKS.md). First three rows: receiver checks and discards the data (--sink); last row: real writes.",
    fmt=lambda v: f"{v:.1f} Gbit/s" if v else "0", label_w=200, ref=(10, "10 Gbit/s link"),
)

# 5. The same test set over the versions (BENCHMARKS.md).
chart(
    "versions",
    "The same 19.1 GB test set (85,513 files) over scopy's versions",
    "\u201cClient done\u201d = all data with the receiver (RAM staging since 0.6); \u201con disk\u201d = written and flushed.",
    [
        ("0.3", [None, 559]),
        ("0.4", [None, 389]),
        ("0.5 (source in RAM)", [None, 131]),
        ("0.6 (RAM staging)", [33, 148]),
        ("0.7 (stage auto)", [31, 69]),
        ("0.8.3", [16, 98]),
        ("0.11 (TLS, as the user)", [18, 68]),
    ],
    [("client done", "s1"), ("on disk", "s2")],
    600, [0, 120, 240, 360, 480, 600],
    "0.3–0.6: two other servers; 0.7+: two test VMs. 10 Gbit LAN. Before 0.6 the client waited for the disk.",
    label_w=200,
)
print("charts written to", os.path.normpath(OUT))
