"""
Renders ReportDataOut into a branded PDF via a headless Chromium instance
(Playwright). The HTML built here is self-contained — its own inline CSS, no
dependency on the live frontend being reachable — so PDF generation works
identically whether it's triggered by a user clicking "download" or by the
scheduled-report background job emailing it to someone who never opens the app.

WeasyPrint was tried first (pure Python, no browser) but requires native
GTK/Pango libraries that aren't installed on Windows and need a separate
manual runtime setup — Playwright ships its own browser binary via
`playwright install chromium` and has no such dependency.
"""
from __future__ import annotations

from playwright.async_api import async_playwright

from app.schemas.overview import ReportDataOut


def _grade_color(grade: str) -> str:
    return {"A": "#34e0a1", "B": "#5b6ef5", "C": "#f5c542", "D": "#ff8c42", "F": "#ff4d6d"}.get(grade, "#888")


def _sparkline_svg(points: list[int], width: int = 280, height: int = 50) -> str:
    if len(points) < 2:
        return ""
    lo, hi = min(points), max(points)
    span = (hi - lo) or 1
    step = width / (len(points) - 1)
    coords = " ".join(
        f"{i * step:.1f},{height - ((p - lo) / span) * (height - 8) - 4:.1f}"
        for i, p in enumerate(points)
    )
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<polyline points="{coords}" fill="none" stroke="#5b6ef5" stroke-width="2.5"/>'
        f"</svg>"
    )


def _sender_rows_html(rows: list, empty_label: str) -> str:
    if not rows:
        return f'<tr><td colspan="4" class="empty">{empty_label}</td></tr>'
    out = []
    for r in rows[:8]:
        out.append(
            f"<tr><td>{r.org}</td><td>{r.volume:,}</td>"
            f"<td>{r.pass_pct:.0f}%</td><td>{r.dkim_aligned_pct:.0f}% / {r.spf_aligned_pct:.0f}%</td></tr>"
        )
    return "".join(out)


def _domain_rows_html(rows: list) -> str:
    out = []
    for d in rows:
        comp = f"{d.dmarc_comp:.0f}%" if d.dmarc_comp is not None else "—"
        out.append(
            f'<tr><td>{d.domain}</td>'
            f'<td><span class="grade-pill" style="background:{d.grade_color}22;color:{d.grade_color}">{d.grade}</span></td>'
            f'<td>{d.dmarc_stage}</td><td>{d.mta_sts_stage}</td><td>{comp}</td>'
            f'<td class="issue">{d.primary_issue or "—"}</td></tr>'
        )
    return "".join(out)


def _recommendation_rows_html(items: list) -> str:
    if not items:
        return '<div class="empty">No outstanding recommendations — fully hardened.</div>'
    out = []
    for r in items[:10]:
        out.append(
            f'<div class="rec-row"><span class="rec-pri">{r.priority}</span>'
            f'<div><div class="rec-action">{r.action} <span class="rec-domain">— {r.domain}</span></div>'
            f'<div class="rec-detail">{r.detail}</div></div>'
            f'<span class="rec-tag">{r.effort} effort / {r.impact} impact</span></div>'
        )
    return "".join(out)


def build_report_html(report: ReportDataOut, brand_name: str | None = None) -> str:
    s = report.sentinel
    brand = brand_name or "Sentinel"
    spark = _sparkline_svg([p.score for p in report.score_trend])

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page {{ size: A4; margin: 22mm 16mm; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: #1a1a2e; font-size: 11px; }}
  h1, h2, h3 {{ font-family: Georgia, serif; margin: 0; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 3px solid #5b6ef5; padding-bottom: 12px; margin-bottom: 22px; }}
  .brand {{ font-size: 20px; font-weight: 800; }}
  .brand b {{ color: #5b6ef5; }}
  .meta {{ text-align: right; color: #666; font-size: 10px; }}
  .score-hero {{ display: flex; gap: 24px; align-items: center; background: #0c0e1c; color: #fff; border-radius: 14px; padding: 20px 26px; margin-bottom: 22px; }}
  .score-num {{ font-size: 52px; font-weight: 800; }}
  .score-grade {{ font-size: 24px; font-weight: 800; }}
  .score-label {{ color: #9aa6ff; font-size: 12px; }}
  .pillars {{ display: flex; gap: 18px; margin-left: auto; }}
  .pillar {{ text-align: center; }}
  .pillar-val {{ font-size: 16px; font-weight: 700; }}
  .pillar-lbl {{ font-size: 9px; color: #888; text-transform: uppercase; letter-spacing: .5px; }}
  .section {{ margin-bottom: 20px; }}
  .section h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .8px; color: #5b6ef5; margin-bottom: 8px; }}
  .narrative {{ line-height: 1.6; color: #333; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
  th {{ text-align: left; text-transform: uppercase; font-size: 8.5px; letter-spacing: .5px; color: #888; padding: 5px 8px; border-bottom: 1px solid #ddd; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
  .grade-pill {{ padding: 1px 7px; border-radius: 8px; font-weight: 700; font-size: 9px; }}
  .issue {{ color: #b9460c; font-size: 9.5px; }}
  .empty {{ color: #999; text-align: center; padding: 10px; }}
  .stat-row {{ display: flex; gap: 16px; margin-bottom: 14px; }}
  .stat {{ background: #f5f6fb; border-radius: 10px; padding: 10px 14px; flex: 1; }}
  .stat-val {{ font-size: 18px; font-weight: 800; }}
  .stat-lbl {{ font-size: 8.5px; color: #888; text-transform: uppercase; }}
  .rec-row {{ display: flex; gap: 10px; align-items: flex-start; padding: 8px 0; border-bottom: 1px solid #eee; }}
  .rec-pri {{ background: #5b6ef522; color: #5b6ef5; border-radius: 50%; width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 9px; flex: none; }}
  .rec-action {{ font-weight: 700; font-size: 10.5px; }}
  .rec-domain {{ color: #888; font-weight: 400; }}
  .rec-detail {{ color: #555; font-size: 9.5px; margin-top: 2px; }}
  .rec-tag {{ margin-left: auto; font-size: 8.5px; color: #888; white-space: nowrap; }}
  .footer {{ margin-top: 24px; padding-top: 10px; border-top: 1px solid #ddd; color: #999; font-size: 8.5px; }}
</style></head>
<body>
  <div class="header">
    <div class="brand">{brand}</div>
    <div class="meta">{report.workspace_name}<br>Generated {report.generated_at[:10]} · last {report.period_days} days</div>
  </div>

  <div class="score-hero">
    <div>
      <div class="score-num">{s.score}<span style="font-size:18px;color:#888">/100</span></div>
    </div>
    <div>
      <div class="score-grade" style="color:{_grade_color(s.grade)}">{s.grade}</div>
      <div class="score-label">{s.grade_label}</div>
    </div>
    <div class="pillars">
      <div class="pillar"><div class="pillar-val">{s.pillar_dmarc:.0f}/60</div><div class="pillar-lbl">DMARC</div></div>
      <div class="pillar"><div class="pillar-val">{s.pillar_tls:.0f}/25</div><div class="pillar-lbl">MTA-STS</div></div>
      <div class="pillar"><div class="pillar-val">{s.pillar_certs:.0f}/15</div><div class="pillar-lbl">Certs</div></div>
    </div>
    {f'<div>{spark}</div>' if spark else ''}
  </div>

  <div class="section">
    <h2>Executive summary</h2>
    <p class="narrative">{report.executive_narrative}</p>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="stat-val">{report.total_domains}</div><div class="stat-lbl">Domains monitored</div></div>
    <div class="stat"><div class="stat-val">{report.dmarc_reject_count}</div><div class="stat-lbl">Fully enforced</div></div>
    <div class="stat"><div class="stat-val">{report.threat.blocked_pct:.0f}%</div><div class="stat-lbl">Impersonation blocked</div></div>
    <div class="stat"><div class="stat-val">{report.cert_alerts}</div><div class="stat-lbl">Cert alerts</div></div>
  </div>

  <div class="section">
    <h2>Domain posture</h2>
    <table>
      <thead><tr><th>Domain</th><th>Grade</th><th>DMARC</th><th>MTA-STS</th><th>Compliance</th><th>Primary issue</th></tr></thead>
      <tbody>{_domain_rows_html(report.domains)}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Prioritised recommendations</h2>
    {_recommendation_rows_html(report.recommendations)}
  </div>

  <div class="section">
    <h2>Sender inventory — authorized &amp; compliant</h2>
    <table>
      <thead><tr><th>Source</th><th>Volume</th><th>Pass rate</th><th>DKIM / SPF aligned</th></tr></thead>
      <tbody>{_sender_rows_html(report.sender_inventory.authorized_compliant, "No data yet")}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Sender inventory — unauthorized / suspicious</h2>
    <table>
      <thead><tr><th>Source</th><th>Volume</th><th>Pass rate</th><th>DKIM / SPF aligned</th></tr></thead>
      <tbody>{_sender_rows_html(report.sender_inventory.unauthorized, "None detected")}</tbody>
    </table>
  </div>

  <div class="footer">{brand} — DMARC &amp; MTA-STS email security monitoring. This report reflects data collected over the last {report.period_days} days.</div>
</body></html>"""


async def render_report_pdf(report: ReportDataOut, brand_name: str | None = None) -> bytes:
    html = build_report_html(report, brand_name)
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            page = await browser.new_page()
            await page.set_content(html, wait_until="load")
            pdf_bytes = await page.pdf(format="A4", print_background=True)
        finally:
            await browser.close()
    return pdf_bytes
