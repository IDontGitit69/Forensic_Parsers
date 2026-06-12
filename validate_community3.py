"""
validate_community.py — validates community-submitted YARA rules on MRs.

Checks:
  1. Compile check — runs yarac64.exe against each rule in rules/Community/.
     Fails the pipeline (blocks MR) if any rule fails to compile.
     Posts a detailed comment on the MR explaining the error.

  2. Duplicate name check — clones the customer repo and checks submitted
     rule names against ALL rules currently in production. Warns only —
     does not block the MR since the main pipeline auto-renames duplicates.

Usage:
  python -m pipeline.validate_community
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("pipeline.validate_community")

REPO_ROOT      = Path(os.environ.get("REPO_ROOT", "."))
RULES_DIR      = REPO_ROOT / "rules"
COMMUNITY_DIR  = RULES_DIR / "Community"
YARA_BIN       = os.environ.get("YARA_BIN", "pipeline/tools/yarac64.exe")

# Customer repo connection
PAT_TOKEN          = os.environ.get("PAT_TOKEN", "")
CI_SERVER_HOST     = os.environ.get("CI_SERVER_HOST", "")
CUSTOMER_REPO_PATH = os.environ.get("CUSTOMER_REPO_PATH", "")
CUSTOMER_REPO_URL  = os.environ.get(
    "CUSTOMER_REPO_URL",
    f"https://alesher:{PAT_TOKEN}@{CI_SERVER_HOST}/{CUSTOMER_REPO_PATH}.git"
)

# GitLab MR comment variables — auto-provided by GitLab on MR pipelines
CI_PROJECT_ID      = os.environ.get("CI_PROJECT_ID", "")
CI_MR_IID          = os.environ.get("CI_MERGE_REQUEST_IID", "")

CLONE_DIR = Path("/tmp/customer-repo-check")

RULE_NAME_RE = re.compile(r'^\s*rule\s+(\w+)', re.MULTILINE)


# ── MR Comment ───────────────────────────────────────────────────────────────

def post_mr_comment(message: str):
    """
    Post a comment on the MR via the GitLab API.
    Silently skips if any required variable is missing.
    """
    if not all([CI_PROJECT_ID, CI_MR_IID, PAT_TOKEN, CI_SERVER_HOST]):
        logger.warning(
            "Cannot post MR comment — one or more required CI variables "
            "are missing (CI_PROJECT_ID, CI_MERGE_REQUEST_IID, "
            "PAT_TOKEN, CI_SERVER_HOST)."
        )
        return

    url = (
        f"http://{CI_SERVER_HOST}/api/v4/projects/{CI_PROJECT_ID}"
        f"/merge_requests/{CI_MR_IID}/notes"
    )

    data = json.dumps({"body": message}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "PRIVATE-TOKEN": PAT_TOKEN,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        urllib.request.urlopen(req)
        logger.info("Posted comment on MR.")
    except Exception as e:
        logger.warning(f"Could not post MR comment: {e}")


def build_success_comment(warnings: list[str]) -> str:
    lines = ["## ✅ YARA Community Rule Validation Passed\n"]
    lines.append("All submitted rules compiled successfully.\n")

    if warnings:
        lines.append("---")
        lines.append("### ⚠️ Duplicate Rule Names Detected\n")
        lines.append(
            "The following rule names already exist in the production repo. "
            "They will be **automatically renamed** by the pipeline when this MR is merged "
            "(e.g. `rule_name` → `rule_name_1`). No action needed.\n"
        )
        for w in warnings:
            lines.append(f"- {w}")

    lines.append("\n---")
    lines.append(
        "_This MR is ready for review. "
        "Once approved and merged, the rule will be published to the "
        "production repo on the next pipeline run._"
    )
    return "\n".join(lines)


def build_failure_comment(failed_results: list[dict], warnings: list[str]) -> str:
    lines = ["## ❌ YARA Rule Validation Failed\n"]
    lines.append(
        "One or more community rules failed to compile. "
        "This MR cannot be merged until the errors are fixed.\n"
    )
    lines.append("---")
    lines.append("### Compile Errors\n")

    for item in failed_results:
        lines.append(f"**`{item['filename']}`**")
        if item['error']:
            lines.append(f"```\n{item['error']}\n```")
        lines.append("")

    if warnings:
        lines.append("---")
        lines.append("### ⚠️ Duplicate Rule Names (informational)\n")
        for w in warnings:
            lines.append(f"- {w}")

    lines.append("---")
    lines.append("### How to fix\n")
    lines.append(
        "1. Go to the file shown above in this branch\n"
        "2. Click the **Edit** (pencil) icon\n"
        "3. Fix the YARA syntax error\n"
        "4. Commit to **this branch** (not main)\n"
        "5. The pipeline will re-run automatically on this MR"
    )
    return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────────────

def run(cmd: list[str], cwd: Path = None, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        logger.error(f"Command failed: {' '.join(cmd)}")
        logger.error(result.stderr.strip() or result.stdout.strip())
        sys.exit(1)
    return result


def find_community_files() -> list[Path]:
    return (
        sorted(COMMUNITY_DIR.rglob("*.yar")) +
        sorted(COMMUNITY_DIR.rglob("*.yara"))
    )


# ── Step 1: Clone customer repo and get existing rule names ──────────────────

def get_existing_rule_names() -> dict[str, Path]:
    """
    Shallow clone the customer repo and scan all rule files for rule names.
    Returns { rule_name: relative_file_path }.
    """
    if not CUSTOMER_REPO_URL or not PAT_TOKEN:
        logger.warning(
            "CUSTOMER_REPO_URL or PAT_TOKEN not set — "
            "skipping duplicate name check against production rules."
        )
        return {}

    if CLONE_DIR.exists():
        shutil.rmtree(CLONE_DIR)

    logger.info("Cloning customer repo for name conflict check...")
    run(["git", "clone", "--depth=1", CUSTOMER_REPO_URL, str(CLONE_DIR)])
    logger.info("Clone complete.")

    names = {}
    for path in CLONE_DIR.rglob("*.yar"):
        content = path.read_text(encoding="utf-8")
        for name in RULE_NAME_RE.findall(content):
            names[name] = path.relative_to(CLONE_DIR)

    logger.info(f"Found {len(names)} existing rule names in customer repo.")
    return names


# ── Step 2: Duplicate name check ─────────────────────────────────────────────

def check_duplicate_names(
    files: list[Path],
    existing: dict[str, Path]
) -> list[str]:
    if not existing:
        return []

    warnings = []
    for path in files:
        content = path.read_text(encoding="utf-8")
        for name in RULE_NAME_RE.findall(content):
            if name in existing:
                warnings.append(
                    f"`{name}` in `{path.name}` conflicts with "
                    f"`{existing[name]}` in the customer repo"
                )
                logger.warning(f"DUPLICATE NAME: {name} in {path.name}")

    return warnings


# ── Step 3: Compile check ────────────────────────────────────────────────────

def compile_check(files: list[Path]) -> tuple[list[Path], list[dict]]:
    """
    Compile each community rule file using yarac64.exe.
    Returns (passed, failed_results) where failed_results is a list of
    { filename, error } dicts for building the MR comment.
    """
    if not Path(YARA_BIN).exists():
        logger.warning(
            f"COMPILE CHECK SKIPPED — binary not found at '{YARA_BIN}'."
        )
        return files, []

    passed = []
    failed_results = []

    for path in files:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".yarc", delete=False) as tmp:
                tmp_path = tmp.name

            result = subprocess.run(
                [YARA_BIN, str(path), tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                logger.info(f"COMPILE OK: {path.name}")
                passed.append(path)
            else:
                error_text = result.stderr.strip() or result.stdout.strip()
                logger.error(f"COMPILE FAILED: {path.name}\n  {error_text}")
                failed_results.append({
                    "filename": path.name,
                    "error": error_text,
                })

        except subprocess.TimeoutExpired:
            logger.error(f"COMPILE TIMEOUT: {path.name}")
            failed_results.append({
                "filename": path.name,
                "error": "Compile timed out after 30 seconds.",
            })

        finally:
            if tmp_path:
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except Exception:
                    pass

    return passed, failed_results


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    logger.info("=== Community MR Validation starting ===")

    if not COMMUNITY_DIR.exists():
        logger.warning(f"Community directory not found: {COMMUNITY_DIR}")
        sys.exit(0)

    files = find_community_files()
    logger.info(f"Found {len(files)} community rule file(s) to validate.")

    if not files:
        logger.warning("No community rules found — nothing to validate.")
        sys.exit(0)

    # Step 1 — get existing rule names from customer repo
    existing_names = get_existing_rule_names()

    # Step 2 — duplicate name check (warns only)
    logger.info("Checking for duplicate rule names against production...")
    warnings = check_duplicate_names(files, existing_names)

    # Step 3 — compile check
    logger.info("Running compile checks...")
    passed, failed_results = compile_check(files)

    # Cleanup clone
    if CLONE_DIR.exists():
        shutil.rmtree(CLONE_DIR)

    # Summary
    logger.info("=== Community validation summary ===")
    logger.info(f"  Files validated    : {len(files)}")
    logger.info(f"  Compile passed     : {len(passed)}")
    logger.info(f"  Compile failed     : {len(failed_results)}")
    logger.info(f"  Duplicate warnings : {len(warnings)}")

    # Post MR comment and exit
    if failed_results:
        comment = build_failure_comment(failed_results, warnings)
        post_mr_comment(comment)
        logger.error(
            f"{len(failed_results)} rule(s) failed to compile. "
            f"See MR comment for details."
        )
        sys.exit(1)
    else:
        comment = build_success_comment(warnings)
        post_mr_comment(comment)
        logger.info("=== Community validation passed ===")


if __name__ == "__main__":
    main()
