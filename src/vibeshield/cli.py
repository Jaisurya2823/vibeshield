from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .baseline import load_baseline, save_baseline, split_by_baseline
from .graph import run_graph
from .reporting import build_report_summary
from .sarif_export import build_sarif

load_dotenv()

app = typer.Typer(add_completion=False)
console = Console()


@app.command()
def main(
    path: str = typer.Argument(..., metavar="PATH"),
    offline: bool = typer.Option(False, "--offline", help="Disable any LLM-backed analysis and use local rules only."),
    update_baseline: bool = typer.Option(
        False, "--update-baseline",
        help="Accept all current findings as known/reviewed. Future scans won't re-report them.",
    ),
    no_baseline: bool = typer.Option(
        False, "--no-baseline",
        help="Ignore any existing baseline file and show every finding, including previously accepted ones.",
    ),
    sarif: str = typer.Option(
        None, "--sarif",
        help="Write results as a SARIF 2.1.0 file at this path, for GitHub Code Scanning / IDE integration.",
    ),
) -> None:
    resolved_path = Path(path).resolve()

    if not resolved_path.exists():
        console.print(f"[bold red]Error:[/bold red] path does not exist: {resolved_path}")
        console.print("[dim]Nothing was scanned -- this is not a clean-scan result, it's an invalid invocation.[/dim]")
        raise typer.Exit(code=2)

    if not resolved_path.is_dir():
        console.print(f"[bold red]Error:[/bold red] path is not a directory: {resolved_path}")
        console.print("[dim]vibeshield scans a folder, not a single file.[/dim]")
        raise typer.Exit(code=2)

    os.environ["VIBESHIELD_OFFLINE"] = "1" if offline or os.getenv("VIBESHIELD_OFFLINE", "0").lower() in {"1", "true", "yes"} else "0"
    state = run_graph(path)

    baseline_path = resolved_path / ".vibeshield-baseline.json"
    suppressed_count = 0

    if update_baseline:
        save_baseline(baseline_path, state.vulnerabilities)
    elif not no_baseline:
        accepted = load_baseline(baseline_path)
        if accepted:
            new_findings, suppressed = split_by_baseline(state.vulnerabilities, accepted)
            state.vulnerabilities = new_findings
            suppressed_count = len(suppressed)

    console.print(Panel.fit(f"vibeshield report for {resolved_path}", style="bold cyan"))
    console.print("\n[bold]Executive summary[/bold]")

    if sarif:
        sarif_doc = build_sarif(state)
        sarif_path = Path(sarif)
        sarif_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        console.print(f"[dim]SARIF report written to {sarif_path} ({len(state.vulnerabilities)} result(s)).[/dim]")

    if update_baseline:
        console.print(
            f"[bold green]Baseline updated:[/bold green] {len(state.vulnerabilities)} finding(s) recorded as "
            f"accepted at {baseline_path.name}. Future scans will only report NEW findings beyond these."
        )
    elif suppressed_count:
        console.print(
            f"[dim]{suppressed_count} previously-accepted finding(s) suppressed via {baseline_path.name} "
            f"(use --no-baseline to see everything, including these).[/dim]"
        )

    if len(state.files) == 0:
        console.print("[bold yellow]Warning:[/bold yellow] 0 files matched this scan (empty directory, or "
                       "everything was excluded/filtered). This is NOT the same as a clean scan -- there was "
                       "nothing here to check.")

    truncated_files = [f.rel_path for f in state.files if f.truncated]
    if truncated_files:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] {len(truncated_files)} file(s) exceeded the read limit "
            f"and were only partially scanned -- findings past the cutoff point are NOT reported. "
            f"This is not a clean-scan guarantee for these files: {', '.join(truncated_files[:5])}"
            + (f" (+{len(truncated_files) - 5} more)" if len(truncated_files) > 5 else "")
        )

    if state.unreadable_files:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] {len(state.unreadable_files)} file(s) could not be read "
            f"(permission denied, broken symlink, or removed mid-scan) and were skipped entirely -- "
            f"this is NOT a clean-scan guarantee for these files: {', '.join(state.unreadable_files[:5])}"
            + (f" (+{len(state.unreadable_files) - 5} more)" if len(state.unreadable_files) > 5 else "")
        )

    if state.llm_error:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] LLM calls were enabled but failed "
            f"({state.llm_error}) -- results below are static-rules-only, not a silent 'nothing found' "
            f"from the LLM. Check your GROQ_API_KEY and network access."
        )

    console.print(f"- {build_report_summary(state)}")
    console.print("- Files scanned: {}".format(len(state.files)))
    console.print("- Risk surfaces: {}".format(len(state.risk_surfaces)))

    confirmed = sum(1 for s in state.risk_surfaces if s.confidence == "confirmed")
    inferred = sum(1 for s in state.risk_surfaces if s.confidence == "inferred")
    unverified = sum(1 for s in state.risk_surfaces if s.confidence == "inferred-unverified")
    if inferred or unverified:
        console.print(
            f"  ({confirmed} confirmed by static rules, {inferred} inferred by LLM "
            f"and verified against the file, {unverified} LLM claims rejected as unverified)"
        )
    elif state.risk_surfaces:
        console.print(f"  (all {confirmed} confirmed by static rules -- no LLM call was made this run)")

    if state.risk_surfaces:
        rs_table = Table(title="Risk surfaces")
        rs_table.add_column("File")
        rs_table.add_column("Line")
        rs_table.add_column("Entry point")
        rs_table.add_column("Confidence")
        rs_table.add_column("Why (LLM rationale)")
        for rs in state.risk_surfaces:
            style = {"confirmed": "green", "inferred": "yellow", "inferred-unverified": "dim"}.get(rs.confidence, "")
            rationale = rs.rationale if rs.confidence != "confirmed" else "-"
            rs_table.add_row(
                rs.rel_path, str(rs.line) if rs.line else "-", rs.entry_point,
                f"[{style}]{rs.confidence}[/{style}]", rationale,
            )
        console.print(rs_table)

    if state.vulnerabilities:
        table = Table(title="Detected vulnerabilities")
        table.add_column("File")
        table.add_column("Category")
        table.add_column("Severity")
        table.add_column("Summary")
        for vuln in state.vulnerabilities:
            table.add_row(vuln.rel_path, vuln.category, vuln.severity, vuln.summary)
        console.print(table)

        for vuln in state.vulnerabilities:
            console.print(Panel.fit(f"[bold]{vuln.rel_path}[/bold]\n\nCategory: {vuln.category}\nSeverity: {vuln.severity}\nEvidence: {vuln.evidence}\nRemediation: {vuln.remediation}", style="red"))
    else:
        console.print("No vulnerabilities detected.")

    actionable_items = [item for item in state.findings if item and not item.startswith("Scanned") and not item.startswith("Identified") and not item.startswith("Detected")]
    if actionable_items:
        console.print("\n[bold]Developer guidance[/bold]")
        for item in actionable_items[:4]:
            console.print(f"- {item}")


if __name__ == "__main__":
    sys.exit(main())