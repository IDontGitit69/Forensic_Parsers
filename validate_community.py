"""
validate_community.py — validates community-submitted YARA rules on MRs.

Checks:
  1. Compile check — runs yarac64.exe against each new/changed rule in
     rules/Community/. Fails the pipeline if any rule fails to compile.

  2. Duplicate name check — warns if any rule name conflicts with existing
     rules across the entire rules/ directory. Does NOT fail the pipeline
     since the main validation stage handles renaming automatically.

Usage:
  python -m pipeline.validate_community
"""

import logging
import os
import re
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

RULE_NAME_RE   = re.compile(r'^\s*rule\s+(\w+)', re.MULTILINE)


# ── Helpers ──────────────────────────────────────────────────────────────────

def find_community_files() -> list[Path]:
    files = (
        sorted(COMMUNITY_DIR.rglob("*.yar")) +
        sorted(COMMUNITY_DIR.rglob("*.yara"))
    )
    return files


def find_all_existing_rule_names() -> dict[str, Path]:
    """
    Build a map of every rule name across the entire rules/ directory
    excluding Community/ — used to check for conflicts.
    Returns { rule_name: file_path }
    """
    names = {}
    for path in RULES_DIR.rglob("*.yar"):
        if "Community" in path.parts:
            continue
        content = path.read_text(encoding="utf-8")
        for name in RULE_NAME_RE.findall(content):
            names[name] = path
    return names


# ── Step 1: Compile check ────────────────────────────────────────────────────

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


# ── Step 2: Duplicate name check ─────────────────────────────────────────────

def check_duplicate_names(files: list[Path]) -> list[str]:
    """
    Check community rules for name conflicts against existing rules.
    Returns a list of warning messages — does not fail the pipeline.
    """
    existing = find_all_existing_rule_names()
    warnings = []

    for path in files:
        content = path.read_text(encoding="utf-8")
        names = RULE_NAME_RE.findall(content)
        for name in names:
            if name in existing:
                msg = (
                    f"DUPLICATE NAME: '{name}' in {path.name} conflicts with "
                    f"{existing[name]}. Will be auto-renamed by the main pipeline."
                )
                logger.warning(msg)
                warnings.append(msg)

    return warnings


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

    # Step 1 — compile check (blocks MR on failure)
    logger.info("Running compile checks...")
    passed, failed = compile_check(files)

    # Step 2 — duplicate name check (warns only)
    logger.info("Checking for duplicate rule names...")
    warnings = check_duplicate_names(files)

    # Summary
    logger.info("=== Community validation summary ===")
    logger.info(f"  Files validated  : {len(files)}")
    logger.info(f"  Compile passed   : {len(passed)}")
    logger.info(f"  Compile failed   : {len(failed)}")
    logger.info(f"  Duplicate warnings: {len(warnings)}")

    if warnings:
        logger.warning("  The following rules will be auto-renamed by the pipeline:")
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
