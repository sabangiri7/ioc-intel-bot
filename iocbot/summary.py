from __future__ import annotations

from pathlib import Path


def write_summary(path: Path, stats: dict) -> str:
    lines: list[str] = []
    add = lines.append
    add("=" * 78)
    add("IOC INTELLIGENCE COLLECTION BOT — IOC_SUMMARY.txt")
    add("=" * 78)
    add(f"Cycle ID           : {stats.get('cycle_id')}")
    add(f"Duration (seconds) : {stats.get('duration_seconds')}")
    add(f"First run          : {stats.get('first_run')}")
    add("")

    add("-" * 78)
    add("TOTALS (unique IOCs in master database)")
    add("-" * 78)
    totals = stats.get("totals", {})
    for key in sorted(totals):
        if str(key) == "total" or ":" in str(key):
            add(f"  {key:<34} {totals[key]}")
    add("")

    add("-" * 78)
    add("EXPORT COUNTS (rows written this cycle)")
    add("-" * 78)
    for name, count in sorted((stats.get("export_counts") or {}).items()):
        add(f"  {name:<34} {count}")
    add("")

    add("-" * 78)
    add("SOURCE RESULTS")
    add("-" * 78)
    for s in stats.get("sources", []):
        status = "OK" if s.get("fetched") else "FAILED"
        detail = (
            f"  {s.get('source', '?'):<26} {s.get('kind', '?'):<14} {status:<7} "
            f"mentions={s.get('mentions', 0)}"
        )
        if s.get("articles") is not None and "articles" in s:
            detail += f" articles={s.get('articles', 0)}"
        if s.get("entries") is not None and "entries" in s:
            detail += f" entries={s.get('entries', 0)}"
        add(detail)
        for err in (s.get("errors") or [])[:5]:
            add(f"      error: {err}")
    add("")

    add("-" * 78)
    add("PROCESSING")
    add("-" * 78)
    proc = stats.get("processing", {})
    add(f"  Mentions collected       : {stats.get('mentions_total', 0)}")
    add(f"  Mentions accepted        : {proc.get('accepted', 0)}")
    add(f"  Mentions rejected        : {proc.get('rejected', 0)}")
    reasons = proc.get("reject_reasons", {})
    for reason in sorted(reasons, key=lambda r: -reasons[r]):
        add(f"      {reason:<30} {reasons[reason]}")
    add(f"  Rows scored              : {stats.get('rows_scored', 0)}")
    add(f"  Rows written (upserts)   : {stats.get('rows_written', 0)}")
    add("")

    add("-" * 78)
    add("CONFIDENCE / SEVERITY DISTRIBUTION (master database)")
    add("-" * 78)
    dist = stats.get("distribution", {})
    for section in ("confidence", "severity", "crowdstrike_importable"):
        block = dist.get(section, {})
        if not block:
            continue
        add(f"  {section}:")
        for k in sorted(block, key=lambda x: str(x)):
            add(f"      {str(k):<16} {block[k]}")
    add("")

    add("-" * 78)
    add("NOTES")
    add("-" * 78)
    add("  * All daily CSV files contain a single IOC column (one indicator per line).")
    add("  * CROWDSTRIKE_IOC_IMPORT.csv lists only IOCs that pass the import gate")
    add("    (supported type: ipv4/ipv6/domain/sha256/md5; confidence and severity")
    add("    Medium or above; validation VALID; no shared-platform or")
    add("    legit-service-abused tags). Detect/monitor candidates only.")
    add("  * All output is for manual analyst review and import only.")
    add("  * No blocking action is taken; no CrowdStrike API calls are made;")
    add("    no DNS resolution of indicators; no internal asset queries.")
    add("=" * 78)
    text = "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")
    return text
