"""
validate.py — YARA rule validation for the production pipeline.

Two checks:
  1. Duplicate rule names — finds any rule name that appears more than once
     across ALL .yar/.yara files in the rules/ directory (including within
     the same bundle). Renames duplicates by appending _1, _2, _3 etc.
     directly inside the file and saves the change.

  2. Compilation check — runs yarac64.exe -f against each bundle file to
     ensure it compiles cleanly after deduplication.

Usage:
  python -m pipeline.validate
"""

import logging
import os
import re
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("pipeline.validate")

REPO_ROOT = Path(os.environ.get("REPO_ROOT", "."))
RULES_DIR = REPO_ROOT / "rules"
YARA_BIN  = os.environ.get("YARA_BIN", "pipeline/tools/yarac64.exe")

# Matches: rule RuleName or rule RuleName : tag1 tag2
RULE_NAME_RE = re.compile(r'^\s*rule\s+(\w+)', re.MULTILINE)


# ── Step 1: Deduplication ────────────────────────────────────────────────────

def find_all_rule_files() -> list[Path]:
    files = sorted(RULES_DIR.rglob("*.yar")) + sorted(RULES_DIR.rglob("*.yara"))
    return files


def extract_rule_names(content: str) -> list[str]:
    return RULE_NAME_RE.findall(content)


def deduplicate_rule_names(files: list[Path]) -> dict:
    """
    Scan all rule files, find duplicate rule names across all bundles,
    rename duplicates by appending _1, _2 etc. inside the file content,
    and save the updated files.
    """
    seen: dict[str, list[tuple[Path, str]]] = {}

    for path in files:
        content = path.read_text(encoding="utf-8")
        names = extract_rule_names(content)
        for name in names:
            seen.setdefault(name, []).append((path, name))

    renames: list[str] = []
    all_names: set[str] = set(seen.keys())

    for name, occurrences in seen.items():
        if len(occurrences) <= 1:
            continue

        for idx, (path, original_name) in enumerate(occurrences[1:], start=1):
            counter = idx
            new_name = f"{original_name}_{counter}"

            while new_name in all_names:
                counter += 1
                new_name = f"{original_name}_{counter}"

            all_names.add(new_name)

            content = path.read_text(encoding="utf-8")
            pattern = re.compile(
                r'(^\s*rule\s+)' + re.escape(original_name) + r'(\s)',
                re.MULTILINE
            )
            updated_content = pattern.sub(
                lambda m: f"{m.group(1)}{new_name}{m.group(2)}",
                content,
                count=1
            )
            path.write_text(updated_content, encoding="utf-8")

            msg = f"RENAMED: {original_name} → {new_name} in {path}"
            logger.warning(msg)
            renames.append(msg)

    return {
        "total_rules": sum(len(v) for v in seen.values()),
        "unique_names": len(seen),
        "duplicates_renamed": len(renames),
        "renames": renames,
    }


# ── Step 2: Compilation ──────────────────────────────────────────────────────

def compile_check(files: list[Path]) -> tuple[list[Path], list[Path]] | None:
    """
    Run yarac64.exe -f against each bundle file.
    Returns (passed, failed), or None if the binary is not available.
    """
    if not Path(YARA_BIN).exists():
        logger.warning(
            f"COMPILE CHECK SKIPPED — yarac64.exe not found at '{YARA_BIN}'. "
            f"Ensure pipeline/tools/yarac64.exe exists in the repo."
        )
        return None

    passed = []
    failed = []

    for path in files:
        try:
            result = subprocess.run(
                [YARA_BIN, "-f", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                passed.append(path)
            else:
                logger.error(
                    f"COMPILE FAILED: {path}\n"
                    f"  {result.stderr.strip() or result.stdout.strip()}"
                )
                failed.append(path)
        except subprocess.TimeoutExpired:
            logger.error(f"COMPILE TIMEOUT: {path}")
            failed.append(path)

    return passed, failed


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    logger.info("=== Validate stage starting ===")

    files = find_all_rule_files()
    logger.info(f"Found {len(files)} rule bundle(s) in {RULES_DIR}")

    if not files:
        logger.warning("No rule files found — nothing to validate.")
        sys.exit(0)

    # Step 1 — deduplicate
    logger.info("Checking for duplicate rule names...")
    dedup_summary = deduplicate_rule_names(files)
    logger.info(
        f"Deduplication complete — "
        f"{dedup_summary['total_rules']} rules scanned, "
        f"{dedup_summary['duplicates_renamed']} renamed."
    )

    # Step 2 — compile check
    logger.info("Running compile checks...")
    compile_result = compile_check(files)

    # Summary
    logger.info("=== Validation summary ===")
    logger.info(f"  Rule bundles scanned : {len(files)}")
    logger.info(f"  Total rules found    : {dedup_summary['total_rules']}")
    logger.info(f"  Duplicates renamed   : {dedup_summary['duplicates_renamed']}")

    if compile_result is None:
        logger.warning("  Compile check        : SKIPPED (yarac64.exe unavailable)")
    else:
        passed, failed = compile_result
        logger.info(f"  Compile passed       : {len(passed)}")
        logger.info(f"  Compile failed       : {len(failed)}")
        if failed:
            logger.error("One or more rule bundles failed to compile — see above.")
            sys.exit(1)

    if dedup_summary['renames']:
        logger.info("  Renames:")
        for r in dedup_summary['renames']:
            logger.info(f"    {r}")

    logger.info("=== Validate stage complete ===")


if __name__ == "__main__":
    main()
