#!/usr/bin/env python3
"""ClickOnce Host Finder — discover and score .NET executables for ClickOnce hosting."""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from io import StringIO
from pathlib import Path
from typing import Iterable, Iterator, Optional

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from assembly_analysis import (
    AssemblyReport,
    analyze_assembly,
    architecture_matches_filter,
    pe_quick_scan,
)

DEFAULT_SKIP_DIRS = {
    r"C:\Windows\SxS",
    r"C:\Windows\CCM",
    r"C:\Windows\WinSxS",
    r"C:\Windows\SysWOW64\WinMetadata",
    r"C:\Windows\SysWOW64\WindowsPowerShell",
    r"C:\Windows\SysWOW64\wbem",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\SystemApps",
    r"C:\Windows\System32\WinMetadata",
    r"C:\Windows\System32\WindowsPowerShell",
    r"C:\Windows\System32\wbem",
    r"C:\Windows\Microsoft.NET\Framework64",
    r"C:\Windows\Microsoft.NET\Framework",
    r"C:\Windows\Microsoft.NET\assembly",
    r"C:\Windows\Installer",
    r"C:\Windows\assembly",
    r"C:\Windows\servicing",
    r"C:\Program Files (x86)\dotnet",
    r"C:\Program Files (x86)\Microsoft Visual Studio 14.0",
    r"C:\Program Files (x86)\IIS",
    r"C:\Program Files (x86)\IIS Express",
    r"C:\Program Files (x86)\Microsoft Office",
    r"C:\Program Files (x86)\Microsoft Visual Studio",
    r"C:\Program Files (x86)\Windows Kits",
    r"C:\Program Files (x86)\Reference Assemblies",
    r"C:\Program Files (x86)\Microsoft SDKs",
    r"C:\Program Files (x86)\MSBuild",
    r"C:\Program Files\PowerShell",
    r"C:\Program Files\Microsoft Office",
    r"C:\Program Files\WindowsApps",
    r"C:\Program Files\IIS",
    r"C:\Program Files\dotnet",
    r"C:\Program Files\Reference Assemblies\Microsoft",
    r"C:\Program Files\Microsoft SQL Server",
    r"C:\ProgramData\Microsoft\VisualStudio",
}

DEFAULT_SEARCH_ROOTS = [
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)"),
]

FOUND_ASSEMBLY_RE = re.compile(r"^\[\+\] Found assembly: (.+?)\s*$", re.MULTILINE)
PROGRESS_INTERVAL = 250

PROJECT_DESCRIPTION = (
    "Discover and rank .NET executables on Windows for ClickOnce host suitability. "
    "Scores x86/x64 binaries by Authenticode signing, strong-name/mixed-mode status, "
    "and embedded manifest compatibility."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ClickOnce Host Finder",
        description=PROJECT_DESCRIPTION,
    )
    parser.add_argument(
        "--discovery-tool",
        type=Path,
        help="Optional external .NET discovery executable (key=value CLI, stdout paths)",
    )
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="Directory or file to scan (repeatable). Defaults to Program Files roots.",
    )
    parser.add_argument(
        "--services",
        action="store_true",
        help="Run services=true scan via --discovery-tool",
    )
    parser.add_argument(
        "--tasks",
        action="store_true",
        help="Run tasks=true scan via --discovery-tool",
    )
    parser.add_argument(
        "--autoruns",
        action="store_true",
        help="Run autoruns=true scan via --discovery-tool",
    )
    parser.add_argument(
        "--all-paths",
        action="store_true",
        help="Do not skip common Microsoft-heavy directories during native walks",
    )
    parser.add_argument(
        "--arch",
        choices=["x86", "x64", "msil", "any"],
        default="any",
        help="Filter by architecture (x64 matches amd64)",
    )
    parser.add_argument("--signed-only", action="store_true", help="Only Authenticode-signed executables")
    parser.add_argument("--unsigned-only", action="store_true", help="Only unsigned executables")
    parser.add_argument(
        "--signed-manifest-profile-only",
        action="store_true",
        help="Only binaries matching the signed-manifest profile heuristic",
    )
    parser.add_argument(
        "--manifest-top-identity-only",
        action="store_true",
        help="Only EXEs whose embedded Win32 manifest has an active top-level <assemblyIdentity> node",
    )
    parser.add_argument(
        "--manifest-top-identity-commented-only",
        action="store_true",
        help="Only EXEs where <assemblyIdentity> appears in manifest XML comments but not as an active node",
    )
    parser.add_argument(
        "--no-manifest-top-identity",
        action="store_true",
        help="Only EXEs with no active top-level <assemblyIdentity> in the embedded Win32 manifest",
    )
    parser.add_argument(
        "--clickonce-ready-only",
        action="store_true",
        help="Only show ready or neutralizable targets",
    )
    parser.add_argument(
        "--include-incompatible",
        action="store_true",
        help="Include incompatible results such as FileHistory.exe",
    )
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--output", "-o", type=Path, help="Write results to a file")
    parser.add_argument("--max-results", type=int, default=0, help="Stop after N matches (0 = no limit)")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress messages on stderr",
    )
    return parser.parse_args()


def log_progress(message: str, *, quiet: bool) -> None:
    if not quiet:
        print(message, file=sys.stderr, flush=True)


def run_discovery_tool(exe_path: Path, arguments: list[str]) -> list[Path]:
    result = subprocess.run([str(exe_path), *arguments], capture_output=True, text=True)
    output = (result.stdout or "") + (result.stderr or "")
    return [Path(match.group(1).strip()) for match in FOUND_ASSEMBLY_RE.finditer(output)]


def discovery_tool_scans(
    exe_path: Path,
    search_roots: list[Path],
    *,
    all_paths: bool,
    services: bool,
    tasks: bool,
    autoruns: bool,
) -> list[Path]:
    discovered: list[Path] = []
    seen: set[str] = set()

    def add_paths(paths: Iterable[Path]) -> None:
        for path in paths:
            key = str(path.resolve()).lower()
            if key not in seen:
                seen.add(key)
                discovered.append(path.resolve())

    for root in search_roots:
        if not root.exists():
            continue
        base_args = [f"path={root}", "recurse=true", "exeonly=true", "getarch=true"]
        if all_paths:
            base_args.append("allpaths=true")
        add_paths(run_discovery_tool(exe_path, [*base_args, "signed=true", "clickonce=true"]))
        add_paths(run_discovery_tool(exe_path, [*base_args, "signed=true"]))
        add_paths(run_discovery_tool(exe_path, base_args))

    if services:
        add_paths(run_discovery_tool(exe_path, ["services=true", "signed=true", "getarch=true", "exeonly=true"]))
    if tasks:
        add_paths(run_discovery_tool(exe_path, ["tasks=true", "signed=true", "getarch=true", "exeonly=true"]))
    if autoruns:
        add_paths(run_discovery_tool(exe_path, ["autoruns=true", "signed=true", "getarch=true", "exeonly=true"]))

    return discovered


def should_skip_dir(path: Path, all_paths: bool) -> bool:
    if all_paths:
        return False
    return str(path.resolve()) in DEFAULT_SKIP_DIRS


def iter_native_executables(search_roots: list[Path], *, all_paths: bool) -> Iterator[Path]:
    seen: set[str] = set()

    def walk(directory: Path) -> Iterator[Path]:
        try:
            for child in directory.iterdir():
                if child.is_dir():
                    if not should_skip_dir(child, all_paths):
                        yield from walk(child)
                    continue
                if child.suffix.lower() != ".exe":
                    continue
                key = str(child.resolve()).lower()
                if key in seen:
                    continue
                seen.add(key)
                yield child.resolve()
        except OSError:
            return

    for root in search_roots:
        if root.is_file() and root.suffix.lower() == ".exe":
            key = str(root.resolve()).lower()
            if key not in seen:
                seen.add(key)
                yield root.resolve()
        elif root.is_dir():
            yield from walk(root)


def iter_candidates(
    search_roots: list[Path],
    *,
    all_paths: bool,
    discovery_paths: list[Path],
) -> Iterator[Path]:
    seen: set[str] = set()
    for path in discovery_paths:
        key = str(path.resolve()).lower()
        if key not in seen:
            seen.add(key)
            yield path.resolve()
    for path in iter_native_executables(search_roots, all_paths=all_paths):
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            yield path


def arch_matches(report: AssemblyReport, arch_filter: str) -> bool:
    return architecture_matches_filter(report.architecture, arch_filter)


def passes_filters(report: AssemblyReport, args: argparse.Namespace) -> bool:
    if not arch_matches(report, args.arch):
        return False
    if args.signed_only and not report.authenticode_signed:
        return False
    if args.unsigned_only and report.authenticode_signed:
        return False
    if args.signed_manifest_profile_only and not report.signed_manifest_profile:
        return False
    if args.manifest_top_identity_only and not report.manifest_top_assembly_identity:
        return False
    if args.manifest_top_identity_commented_only and not report.manifest_top_identity_commented:
        return False
    if args.no_manifest_top_identity and report.manifest_top_assembly_identity:
        return False
    if args.clickonce_ready_only and report.clickonce_status not in {"ready", "neutralizable"}:
        return False
    if not args.include_incompatible and report.clickonce_status == "incompatible":
        return False
    return True


def sort_key(report: AssemblyReport) -> tuple:
    status_order = {"ready": 0, "neutralizable": 1, "unknown": 2, "incompatible": 3}
    return (
        status_order.get(report.clickonce_status, 9),
        0 if report.authenticode_signed else 1,
        report.architecture,
        report.path.lower(),
    )


def render_table(reports: list[AssemblyReport]) -> str:
    headers = [
        "status",
        "arch",
        "signed",
        "strong",
        "mixed",
        "sig_profile",
        "top_id",
        "id_comment",
        "dep_id",
        "name",
        "path",
        "notes",
    ]
    rows = [
        [
            report.clickonce_status,
            report.architecture,
            "yes" if report.authenticode_signed else "no",
            "yes" if report.strong_named else "no",
            "yes" if report.mixed_mode else "no",
            "yes" if report.signed_manifest_profile else "no",
            "yes" if report.manifest_top_assembly_identity else "no",
            "yes" if report.manifest_top_identity_commented else "no",
            str(report.manifest_dependency_identities),
            report.name,
            report.path,
            report.clickonce_notes,
        ]
        for report in reports
    ]
    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]

    def fmt_row(values: list[str]) -> str:
        return "  ".join(value.ljust(width) for value, width in zip(values, widths))

    lines = [fmt_row(headers), fmt_row(["-" * width for width in widths])]
    lines.extend(fmt_row(row) for row in rows)
    return "\n".join(lines)


def write_output(reports: list[AssemblyReport], args: argparse.Namespace) -> str:
    if args.format == "json":
        return json.dumps([report.to_dict() for report in reports], indent=2)
    if args.format == "csv":
        if not reports:
            return ""
        fieldnames = list(reports[0].to_dict().keys())
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        for report in reports:
            writer.writerow(report.to_dict())
        return buffer.getvalue()
    return render_table(reports)


def scan_and_collect(args: argparse.Namespace, search_roots: list[Path]) -> list[AssemblyReport]:
    discovery_paths: list[Path] = []
    if args.discovery_tool:
        log_progress(f"Running discovery tool: {args.discovery_tool}", quiet=args.quiet)
        discovery_paths = discovery_tool_scans(
            args.discovery_tool,
            search_roots,
            all_paths=args.all_paths,
            services=args.services,
            tasks=args.tasks,
            autoruns=args.autoruns,
        )
        log_progress(f"Discovery tool returned {len(discovery_paths)} path(s)", quiet=args.quiet)
    else:
        log_progress(
            "Walking directories (use --path to narrow scope, e.g. --path C:\\Windows\\System32)",
            quiet=args.quiet,
        )

    reports: list[AssemblyReport] = []
    scanned = 0
    managed_seen = 0
    analyzed = 0
    started = time.monotonic()

    for path in iter_candidates(
        search_roots,
        all_paths=args.all_paths,
        discovery_paths=discovery_paths,
    ):
        scanned += 1
        if not args.quiet and scanned % PROGRESS_INTERVAL == 0:
            elapsed = time.monotonic() - started
            log_progress(
                f"  … scanned {scanned} .exe | {managed_seen} .NET | "
                f"{analyzed} analyzed | {len(reports)} match(es) | {elapsed:.0f}s",
                quiet=args.quiet,
            )

        quick = pe_quick_scan(path)
        if not quick.managed:
            continue
        managed_seen += 1

        if args.arch != "any" and quick.architecture:
            if not architecture_matches_filter(quick.architecture, args.arch):
                continue

        if args.signed_manifest_profile_only and not quick.embedded_manifest:
            continue

        report = analyze_assembly(path)
        if report is None:
            continue
        analyzed += 1

        if not passes_filters(report, args):
            continue

        reports.append(report)
        if not args.quiet:
            log_progress(f"  + match: {report.name} ({report.clickonce_status}) — {path}", quiet=args.quiet)

        if args.max_results and len(reports) >= args.max_results:
            log_progress(f"Reached --max-results {args.max_results}, stopping early.", quiet=args.quiet)
            break

    elapsed = time.monotonic() - started
    log_progress(
        f"Done in {elapsed:.1f}s: scanned {scanned} .exe, "
        f"{managed_seen} .NET, {analyzed} analyzed, {len(reports)} match(es).",
        quiet=args.quiet,
    )
    return reports


def main() -> None:
    if sys.platform != "win32":
        print("error: ClickOnce Host Finder must run on Windows", file=sys.stderr)
        sys.exit(1)

    args = parse_args()
    if args.signed_only and args.unsigned_only:
        print("error: choose only one of --signed-only or --unsigned-only", file=sys.stderr)
        sys.exit(1)

    identity_filters = sum(
        bool(flag)
        for flag in (
            args.manifest_top_identity_only,
            args.manifest_top_identity_commented_only,
            args.no_manifest_top_identity,
        )
    )
    if identity_filters > 1:
        print(
            "error: choose only one of --manifest-top-identity-only, "
            "--manifest-top-identity-commented-only, or --no-manifest-top-identity",
            file=sys.stderr,
        )
        sys.exit(1)

    if (args.services or args.tasks or args.autoruns) and not args.discovery_tool:
        print("error: --services/--tasks/--autoruns require --discovery-tool", file=sys.stderr)
        sys.exit(1)

    search_roots = [Path(path) for path in args.path] if args.path else DEFAULT_SEARCH_ROOTS
    roots_label = ", ".join(str(root) for root in search_roots)
    log_progress(f"ClickOnce Host Finder — scanning: {roots_label}", quiet=args.quiet)

    if args.discovery_tool and not args.discovery_tool.exists():
        print(f"error: discovery tool not found at {args.discovery_tool}", file=sys.stderr)
        sys.exit(1)

    reports = scan_and_collect(args, search_roots)
    reports.sort(key=sort_key)
    rendered = write_output(reports, args)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {len(reports)} result(s) to {args.output}")
    elif reports:
        print(rendered)
        print(f"\nClickOnce Host Finder: {len(reports)} matching candidate(s).")
    else:
        print("No matching candidates found.")
        print("Try a narrower --path, relax filters, or add --include-incompatible to see rejected binaries.")


if __name__ == "__main__":
    main()
