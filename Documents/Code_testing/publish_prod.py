"""
publish.py — publishes validated rules to the customer-facing repo.

Behavior:
  - Additive/update only — never deletes existing rules
  - New files are added, changed files are updated
  - If nothing changed, no commit is made
  - Commit message includes a summary of what changed

Usage:
  python -m pipeline.publish
"""

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("pipeline.publish")

# ── Config from environment ──────────────────────────────────────────────────

REPO_ROOT = Path(os.environ.get("REPO_ROOT", "."))
RULES_DIR = Path(os.environ.get("RULES_DIR", "rules"))

# Customer repo connection
PAT_TOKEN         = os.environ["PAT_TOKEN"]
CI_SERVER_HOST    = os.environ["CI_SERVER_HOST"]
CUSTOMER_REPO     = os.environ["CUSTOMER_REPO_PATH"]   # e.g. alesher/detection-rules
CUSTOMER_BRANCH   = os.environ.get("CUSTOMER_BRANCH", "main")

CUSTOMER_REPO_URL = f"http://alesher:{PAT_TOKEN}@{CI_SERVER_HOST}/{CUSTOMER_REPO}.git"

# Where to clone the customer repo in the job workspace
CLONE_DIR = Path("/tmp/customer-repo")

# Git identity for the bot commit
GIT_EMAIL = os.environ.get("GIT_BOT_EMAIL", "ci-bot@local")
GIT_NAME  = os.environ.get("GIT_BOT_NAME", "Pipeline Bot")


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


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    logger.info("=== Publish stage starting ===")

    # Verify we have rules to publish
    rule_files = list(RULES_DIR.rglob("*.yar")) + list(RULES_DIR.rglob("*.yara"))
    if not rule_files:
        logger.warning("No validated rules found — nothing to publish.")
        sys.exit(0)

    logger.info(f"Found {len(rule_files)} validated rule files to publish.")

    # ── Clone customer repo ──────────────────────────────────────────────────
    if CLONE_DIR.exists():
        shutil.rmtree(CLONE_DIR)

    logger.info(f"Cloning customer repo...")
    run(["git", "clone", "--depth=1", "-b", CUSTOMER_BRANCH,
         CUSTOMER_REPO_URL, str(CLONE_DIR)])

    # Set git identity
    run(["git", "config", "user.email", GIT_EMAIL], cwd=CLONE_DIR)
    run(["git", "config", "user.name", GIT_NAME], cwd=CLONE_DIR)

    # ── Copy rules into customer repo (additive) ─────────────────────────────
    # Mirror the rules/ directory structure into the customer repo
    # New files are added, changed files are updated, nothing is deleted
    added   = []
    updated = []

    for rule_file in rule_files:
        # Preserve the relative path structure: rules/mandiant/rule.yar
        relative = rule_file.relative_to(REPO_ROOT)
        dest = CLONE_DIR / relative

        dest.parent.mkdir(parents=True, exist_ok=True)

        if not dest.exists():
            shutil.copy2(rule_file, dest)
            added.append(str(relative))
        else:
            # Only copy if content actually changed
            existing = dest.read_text(encoding="utf-8")
            incoming = rule_file.read_text(encoding="utf-8")
            if existing != incoming:
                shutil.copy2(rule_file, dest)
                updated.append(str(relative))

    logger.info(f"Added: {len(added)} | Updated: {len(updated)}")

    # ── Check if anything changed ────────────────────────────────────────────
    rules_subdir = RULES_DIR.name
    run(["git", "add", rules_subdir], cwd=CLONE_DIR)

    diff = run(["git", "diff", "--cached", "--quiet"],
               cwd=CLONE_DIR, check=False)

    if diff.returncode == 0:
        logger.info("No changes detected in customer repo — skipping commit.")
        logger.info("=== Publish stage complete (no changes) ===")
        return

    # ── Commit and push ──────────────────────────────────────────────────────
    # Build a descriptive commit message
    summary_parts = []
    if added:
        summary_parts.append(f"+{len(added)} new")
    if updated:
        summary_parts.append(f"~{len(updated)} updated")
    summary = ", ".join(summary_parts) if summary_parts else "no file changes"

    commit_msg = f"chore: rule update ({summary})"

    run(["git", "commit", "-m", commit_msg], cwd=CLONE_DIR)
    run(["git", "push", "origin", CUSTOMER_BRANCH], cwd=CLONE_DIR)

    logger.info(f"Pushed to {CUSTOMER_REPO} branch '{CUSTOMER_BRANCH}'")
    logger.info(f"  Commit: {commit_msg}")

    if added:
        for f in added:
            logger.info(f"  + {f}")
    if updated:
        for f in updated:
            logger.info(f"  ~ {f}")

    logger.info("=== Publish stage complete ===")


if __name__ == "__main__":
    main()
