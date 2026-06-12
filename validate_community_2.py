"""
validate_community.py — validates community-submitted YARA rules on MRs.

Checks:
  1. Compile check — runs yarac64.exe against each rule in rules/Community/.
     Fails the pipeline (blocks MR) if any rule fails to compile.

  2. Duplicate name check — clones the customer repo and checks submitted
     rule names against ALL rules currently in production. Warns only —
     does not block the MR since the main pipeline auto-renames duplicates.

Usage:
  python -m pipeline.validate_community
"""

import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
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

# Customer repo connection — used to check existing rule names
PAT_TOKEN           = os.environ.get("PAT_TOKEN", "")
CI_SERVER_HOST      = os.environ.get("CI_SERVER_HOST", "")
CUSTOMER_REPO_PATH  = os.environ.get("CUSTOMER_REPO_PATH", "")
CUSTOMER_REPO_URL   = os.environ.get(
    "CUSTOMER_REPO_URL",
    f"https://alesher:{PAT_TOKEN}@{CI_SERVER_HOST}/{CUSTOMER_REPO_PATH}.git"
)

CLONE_DIR = Path("/tmp/customer-repo-check")

RULE_NAME_RE = re.compile(r'^\s*rule\s+(\w+)', re.MULTILINE)


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
    files = (
        sorted(COMMUNITY_DIR.rglob("*.yar")) +
        sorted(COMMUNITY_DIR.rglob("*.yara"))
    )
    return files


# ── Step 1: Clone customer repo and get existing rule names ──────────────────

def get_existing_rule_names() -> dict[str, Path]:
    """
    Shallow clone the customer repo and scan all rule files for rule names.
    Returns { rule_name: file_path } for every rule currently in production.
    """
    if not CUSTOMER_REPO_URL or not PAT_TOKEN:
        logger.warning(
            "CUSTOMER_REPO_URL or PAT_TOKEN not set — "
            "skipping duplicate name check against production rules."
        )
        return {}

    # Clean up any previous clone
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
    """
    Check submitted community rules against existing production rule names.
    Returns warning messages — does not fail the pipeline.
    """
    if not existing:
        return []

    warnings = []
    for path in files:
        content = path.read_text(encoding="utf-8")
        for name in RULE_NAME_RE.findall(content):
            if name in existing:
                msg = (
                    f"DUPLICATE NAME: '{name}' in {path.name} conflicts with "
                    f"{existing[name]} in the customer repo. "
                    f"Will be auto-renamed by the main pipeline."
                )
                logger.warning(msg)
                warnings.append(msg)

    return warnings


# ── Step 3: Compile check ────────────────────────────────────────────────────

def compile_check(files: list[Path]) -> tuple[list[Path], list[Path]]:
    """
    Compile each community rule file using yarac64.exe.
    Returns (passed, failed).
    """
    if not Path(YARA_BIN).exists():
        logger.warning(
            f"COMPILE CHECK SKIPPED — binary not found at '{YARA_BIN}'."
        )
        return files, []

    passed = []
    failed = []

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
                logger.error(
                    f"COMPILE FAILED: {path.name}\n"
                    f"  {result.stderr.strip() or result.stdout.strip()}"
                )
                failed.append(path)

        except subprocess.TimeoutExpired:
            logger.error(f"COMPILE TIMEOUT: {path.name}")
            failed.append(path)

        finally:
            if tmp_path:
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except Exception:
                    pass

    return passed, failed


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

    # Step 3 — compile check (blocks MR on failure)
    logger.info("Running compile checks...")
    passed, failed = compile_check(files)

    # Cleanup clone
    if CLONE_DIR.exists():
        shutil.rmtree(CLONE_DIR)

    # Summary
    logger.info("=== Community validation summary ===")
    logger.info(f"  Files validated    : {len(files)}")
    logger.info(f"  Compile passed     : {len(passed)}")
    logger.info(f"  Compile failed     : {len(failed)}")
    logger.info(f"  Duplicate warnings : {len(warnings)}")

    if warnings:
        logger.warning("  Rules that will be auto-renamed by the pipeline:")
        for w in warnings:
            logger.warning(f"    {w}")

    if failed:
        logger.error(
            f"{len(failed)} rule(s) failed to compile. "
            f"Please fix the errors above before this MR can be merged."
        )
        sys.exit(1)

    logger.info("=== Community validation passed ===")


if __name__ == "__main__":
    main()
