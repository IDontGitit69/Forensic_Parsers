#!/usr/bin/env python3
"""
pipeline/fetchers/fetch_rules.py

Downloads consolidated.yar from S3 and updates rules/consolidated.yar
only if the content has changed.

Expects these env vars (set in GitLab CI/CD settings):
  ACCESS_KEY_ID      - AWS access key
  SECRET_ACCSS_KEY   - AWS secret access key
  S3_BUCKET_NAME     - S3 bucket name
"""

import os
import hashlib
import boto3

# ── Config ─────────────────────────────────────────────────────────────────
S3_KEY       = "consolidated.yar"
RULES_DIR    = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
LOCAL_FILE   = os.path.join(RULES_DIR, S3_KEY)
# ──────────────────────────────────────────────────────────────────────────

def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def main():
    # Read credentials from environment
    access_key    = os.environ["ACCESS_KEY_ID"]
    secret_key    = os.environ["SECRET_ACCSS_KEY"]
    bucket_name   = os.environ["S3_BUCKET_NAME"]

    s3 = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )

    # Download to a temp file first
    tmp_file = LOCAL_FILE + ".tmp"
    os.makedirs(RULES_DIR, exist_ok=True)

    print(f"Downloading s3://{bucket_name}/{S3_KEY} ...")
    s3.download_file(bucket_name, S3_KEY, tmp_file)

    # Compare with existing file
    if os.path.exists(LOCAL_FILE) and md5(LOCAL_FILE) == md5(tmp_file):
        os.remove(tmp_file)
        print("No changes detected — rules are already up to date.")
        return

    os.replace(tmp_file, LOCAL_FILE)
    print(f"Rules updated: {LOCAL_FILE}")

if __name__ == "__main__":
    main()
