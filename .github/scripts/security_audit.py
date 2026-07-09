#!/usr/bin/env python3
"""CI Security Audit — Three-level response mechanism.

Analyzes PR diffs for security risks and responds with:
  - BLOCK: immediately dangerous changes → exit 1, pipeline stops
  - WARN:  long-term risks if merged → PR comment, pipeline continues
  - PASS:  no issues found → pipeline continues

Usage:
  In CI:  python3 security_audit.py
  Local:  python3 security_audit.py --pr 42 --repo owner/repo

Environment:
  GITHUB_EVENT_NAME   - "pull_request" or other
  GITHUB_REPOSITORY   - owner/repo
  GH_TOKEN            - GitHub token (for posting comments)

When not in CI (no GITHUB_EVENT_NAME), runs in local/dry-run mode.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    BLOCK = "block"
    WARN = "warn"


@dataclass
class Finding:
    severity: Severity
    rule: str
    file: str
    line: Optional[int]
    message: str


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_blockers(self) -> bool:
        return any(f.severity == Severity.BLOCK for f in self.findings)

    @property
    def blockers(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.BLOCK]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.WARN]


# ============================================================
# Rules
# ============================================================

# BLOCK-level patterns: immediately expand attack surface
BLOCK_RULES = [
    {
        "id": "pull_request_target",
        "pattern": re.compile(r"^\+.*pull_request_target"),
        "message": "Trigger changed to pull_request_target — allows PR code to run with base branch privileges",
        "file_filter": re.compile(r"\.github/workflows/.*\.ya?ml$"),
    },
    {
        "id": "privileged_container",
        "pattern": re.compile(r"^\+.*--privileged"),
        "message": "Adding --privileged grants container full host access",
        "file_filter": None,
    },
    {
        "id": "remove_security_audit",
        "pattern": re.compile(r"^-.*security.audit", re.IGNORECASE),
        "message": "Removing security-audit job disables the security gate",
        "file_filter": re.compile(r"\.github/workflows/.*\.ya?ml$"),
    },
    {
        "id": "reverse_shell_devtcp",
        "pattern": re.compile(r"^\+.*/dev/tcp/"),
        "message": "Possible reverse shell via /dev/tcp",
        "file_filter": None,
    },
    {
        "id": "reverse_shell_nc",
        "pattern": re.compile(r"^\+.*\bnc\b.*-e\s"),
        "message": "Possible reverse shell via nc -e",
        "file_filter": None,
    },
    {
        "id": "reverse_shell_bash_i",
        "pattern": re.compile(r"^\+.*bash\s+-i\s+>&\s*/dev/"),
        "message": "Possible reverse shell via bash -i",
        "file_filter": None,
    },
]

# WARN-level patterns: long-term risk if merged
WARN_RULES = [
    {
        "id": "permissions_widened",
        "pattern": re.compile(
            r"^\+\s*permissions:\s*(write-all|contents:\s*write|actions:\s*write)"
        ),
        "message": "Workflow permissions widened — verify this is intentional",
        "file_filter": re.compile(r"\.github/workflows/.*\.ya?ml$"),
    },
    {
        "id": "secrets_inherit",
        "pattern": re.compile(r"^\+.*secrets:\s*inherit"),
        "message": "secrets: inherit passes all secrets — prefer explicit listing",
        "file_filter": re.compile(r"\.github/workflows/.*\.ya?ml$"),
    },
    {
        "id": "action_unpinned",
        "pattern": re.compile(r"^\+\s*-?\s*uses:\s*\S+@(main|master|v\d+)\s*$"),
        "message": "Action not pinned to commit hash — vulnerable to upstream compromise",
        "file_filter": re.compile(r"\.github/workflows/.*\.ya?ml$"),
    },
    {
        "id": "cap_add",
        "pattern": re.compile(r"^\+.*--cap-add"),
        "message": "New container capability added — verify necessity",
        "file_filter": None,
    },
    {
        "id": "device_mount",
        "pattern": re.compile(r"^\+.*--device\s"),
        "message": "New device mount added — verify necessity",
        "file_filter": None,
    },
    {
        "id": "external_network_curl",
        "pattern": re.compile(
            r"^\+.*\b(curl|wget)\b.*https?://(?!github\.com|pypi\.org|registry\.npmmirror)"
        ),
        "message": "External network request added — verify the target domain is trusted",
        "file_filter": None,
    },
]


# ============================================================
# Diff parsing
# ============================================================


@dataclass
class DiffHunk:
    file: str
    lines: list[tuple[int, str]]  # (line_number_in_new_file, raw_line)


def get_pr_diff(pr_number: Optional[int] = None, repo: Optional[str] = None) -> str:
    """Get PR diff via gh CLI or GITHUB_EVENT_PATH."""
    if pr_number:
        cmd = ["gh", "pr", "diff", str(pr_number), "--repo", repo or ""]
        cmd = [c for c in cmd if c]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error fetching PR diff: {result.stderr}", file=sys.stderr)
            sys.exit(2)
        return result.stdout

    # In CI: get PR number from event
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and os.path.exists(event_path):
        with open(event_path) as f:
            event = json.load(f)
        pr_num = event.get("pull_request", {}).get("number")
        if pr_num:
            repo = os.environ.get("GITHUB_REPOSITORY", "")
            cmd = ["gh", "pr", "diff", str(pr_num)]
            if repo:
                cmd.extend(["--repo", repo])
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error fetching PR diff: {result.stderr}", file=sys.stderr)
                sys.exit(2)
            return result.stdout

    # Fallback: diff against default branch
    result = subprocess.run(
        ["git", "diff", "origin/main...HEAD"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Try master
        result = subprocess.run(
            ["git", "diff", "origin/master...HEAD"],
            capture_output=True,
            text=True,
        )
    return result.stdout


def parse_diff(diff_text: str) -> list[DiffHunk]:
    """Parse unified diff into structured hunks."""
    hunks: list[DiffHunk] = []
    current_file: Optional[str] = None
    current_lines: list[tuple[int, str]] = []
    line_num = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            if current_file and current_lines:
                hunks.append(DiffHunk(file=current_file, lines=current_lines))
            current_lines = []
            # Extract filename: diff --git a/path b/path
            parts = line.split(" b/", 1)
            current_file = parts[1] if len(parts) > 1 else None
            line_num = 0
        elif line.startswith("@@"):
            # Parse @@ -old,count +new,count @@
            match = re.search(r"\+(\d+)", line)
            if match:
                line_num = int(match.group(1)) - 1
        elif current_file:
            if line.startswith("+") or line.startswith("-"):
                if not line.startswith("+++") and not line.startswith("---"):
                    if line.startswith("+"):
                        line_num += 1
                    current_lines.append((line_num, line))
            else:
                line_num += 1

    if current_file and current_lines:
        hunks.append(DiffHunk(file=current_file, lines=current_lines))

    return hunks


# ============================================================
# Audit engine
# ============================================================


def run_audit(hunks: list[DiffHunk]) -> AuditResult:
    """Run all rules against parsed diff hunks."""
    result = AuditResult()

    for hunk in hunks:
        for line_num, line_text in hunk.lines:
            # Check BLOCK rules
            for rule in BLOCK_RULES:
                if rule["file_filter"] and not rule["file_filter"].search(hunk.file):
                    continue
                if rule["pattern"].search(line_text):
                    result.findings.append(
                        Finding(
                            severity=Severity.BLOCK,
                            rule=rule["id"],
                            file=hunk.file,
                            line=line_num,
                            message=rule["message"],
                        )
                    )

            # Check WARN rules
            for rule in WARN_RULES:
                if rule["file_filter"] and not rule["file_filter"].search(hunk.file):
                    continue
                if rule["pattern"].search(line_text):
                    result.findings.append(
                        Finding(
                            severity=Severity.WARN,
                            rule=rule["id"],
                            file=hunk.file,
                            line=line_num,
                            message=rule["message"],
                        )
                    )

    return result


# ============================================================
# Output formatting
# ============================================================


def format_github_output(result: AuditResult) -> None:
    """Format output for GitHub Actions (annotations + step summary)."""
    summary_lines = []

    if result.has_blockers:
        summary_lines.append("## 🚫 Security Audit: BLOCKED\n")
        summary_lines.append(
            "The following changes immediately expand the attack surface and must be fixed:\n"
        )
        for f in result.blockers:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            summary_lines.append(f"- **[{f.rule}]** `{loc}`: {f.message}")
            # GitHub annotation
            print(f"::error file={f.file},line={f.line or 1}::[{f.rule}] {f.message}")
    elif result.warnings:
        summary_lines.append("## ⚠️ Security Audit: WARNINGS\n")
        summary_lines.append(
            "The following changes introduce long-term risks. Please review before merging:\n"
        )
    else:
        summary_lines.append("## ✅ Security Audit: PASSED\n")
        summary_lines.append("No security issues detected.")

    if result.warnings:
        if not result.has_blockers:
            pass  # Header already added
        else:
            summary_lines.append("\n### Warnings\n")
        for f in result.warnings:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            summary_lines.append(f"- **[{f.rule}]** `{loc}`: {f.message}")
            print(f"::warning file={f.file},line={f.line or 1}::[{f.rule}] {f.message}")

    # Write to GITHUB_STEP_SUMMARY
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write("\n".join(summary_lines) + "\n")
    else:
        # Local mode: print to stdout
        print("\n".join(summary_lines))


def post_pr_comment(result: AuditResult) -> None:
    """Post warnings as PR comment (only for warn-level findings)."""
    if not result.warnings:
        return

    # Only post in CI
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return

    with open(event_path) as f:
        event = json.load(f)
    pr_num = event.get("pull_request", {}).get("number")
    if not pr_num:
        return

    repo = os.environ.get("GITHUB_REPOSITORY", "")

    body_lines = ["## ⚠️ Security Audit Warnings\n"]
    body_lines.append("These are not blocking, but please consider before merging:\n")
    body_lines.append("| Rule | Location | Issue |")
    body_lines.append("|------|----------|-------|")
    for f in result.warnings:
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        body_lines.append(f"| {f.rule} | {loc} | {f.message} |")
    body_lines.append(
        "\n---\n*To skip security audit, add the `skip-security-audit` label (CODEOWNERS only).*"
    )

    body = "\n".join(body_lines)

    cmd = ["gh", "pr", "comment", str(pr_num), "--body", body]
    if repo:
        cmd.extend(["--repo", repo])

    subprocess.run(cmd, capture_output=True, text=True)


# ============================================================
# Main
# ============================================================


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="CI Security Audit")
    parser.add_argument("--pr", type=int, help="PR number (for local testing)")
    parser.add_argument("--repo", type=str, help="Repository (owner/repo)")
    parser.add_argument(
        "--diff-file", type=str, help="Read diff from file instead of gh CLI"
    )
    args = parser.parse_args()

    # Get diff
    if args.diff_file:
        with open(args.diff_file) as f:
            diff_text = f.read()
    else:
        diff_text = get_pr_diff(pr_number=args.pr, repo=args.repo)

    if not diff_text.strip():
        print("No diff found — nothing to audit.")
        sys.exit(0)

    # Parse and audit
    hunks = parse_diff(diff_text)
    result = run_audit(hunks)

    # Output
    format_github_output(result)

    # Post comment for warnings (non-blocking)
    if result.warnings and not result.has_blockers:
        post_pr_comment(result)

    # Exit code
    if result.has_blockers:
        print(
            f"\n❌ Audit BLOCKED: {len(result.blockers)} critical issue(s) found.",
            file=sys.stderr,
        )
        sys.exit(1)
    elif result.warnings:
        print(
            f"\n⚠️  Audit passed with {len(result.warnings)} warning(s).",
            file=sys.stderr,
        )
        sys.exit(0)
    else:
        print("\n✅ Audit passed.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
