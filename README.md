# Detection Rules Pipeline

This repository contains the CI/CD pipeline, fetcher scripts, and validation tooling that powers the automated detection rules lifecycle. It is responsible for ingesting YARA rules from multiple sources, validating and deduplicating them, and publishing a clean ruleset to the [detection-rules-repo](#) (customer-facing repository) which operational environments consume.

> **Note:** This repository does not store rules permanently. Rules exist as CI artifacts during pipeline execution and are published directly to the detection-rules-repo. Rule directories in this repo are placeholders only.

---

## Repository Structure

```
detection-rules-pipeline/
├── .gitlab-ci.yml                  # Pipeline definition
├── pyproject.toml                  # Python package config
├── requirements.txt                # Python dependencies
├── rules/
│   └── Yara/
│       ├── Mandiant/               # Placeholder — populated by fetch stage
│       ├── S3/                     # Placeholder — populated by fetch stage
│       └── Community/              # User-submitted community rules (permanent)
└── pipeline/
    ├── fetchers/
    │   ├── fetch_mandiant.py       # Mandiant API fetcher
    │   ├── fetch_s3.py             # S3 bucket fetcher
    │   └── tools/
    │       ├── yarac64.exe         # YARA compiler binary
    │       ├── validate_prod.py    # Deduplication + compile validation
    │       ├── validate_community.py # Community MR validation
    │       └── publish_prod.py     # Publishes rules to detection-rules-repo
```

---

## Pipeline Overview

The pipeline runs in three stages:

```
fetch → validate → publish
```

| Stage | Job | Trigger |
|---|---|---|
| fetch | `fetch-rules` | Pipeline trigger token (scheduled task) |
| validate | `validate-rules` | Pipeline trigger token OR push to main |
| validate | `validate-community-mr` | MR event touching `rules/Yara/Community/` |
| publish | `publish-rules` | Pipeline trigger token OR push to main |

### Pipeline Triggers

**Scheduled trigger** — A Windows scheduled task on `[RUNNER_HOST]` executes a bash script that fires the GitLab pipeline trigger token via the GitLab API. This kicks off the full `fetch → validate → publish` pipeline on a weekly cadence.

**MR trigger** — When a contributor opens a Merge Request touching `rules/Yara/Community/`, GitLab automatically triggers the `validate-community-mr` job to compile-check the submitted rule before it can be merged.

**Push to main trigger** — When a community MR is approved and merged to main, GitLab triggers `validate → publish` automatically so the new rule is published to the detection-rules-repo without running a full fetch.

---

## Rule Sources

### Mandiant (`rules/Yara/Mandiant/`)
Rules are fetched from the Mandiant Advantage threat intelligence API using `fetch_mandiant.py`. Credentials are stored as masked CI/CD variables (`APIv4_PUBLIC`, `APIv4_SECRET`).

### S3 (`rules/Yara/S3/`)
Rules are fetched from an internal S3 bucket using `fetch_s3.py`. AWS credentials are stored as masked CI/CD variables.

### Community (`rules/Yara/Community/`)
Rules submitted by internal analysts via Merge Request. See [Community Rules](#community-rules--merge-request-workflow) below.

---

## Community Rules — Merge Request Workflow

Community rules live permanently in this repository under `rules/Yara/Community/`. Contributors submit rules via GitLab's web editor without needing to use git directly.

### Submitting a Community Rule

1. Navigate to `rules/Yara/Community/` in this repository
2. Click the **+** button → **New file**
3. Name the file and paste your YARA rule content
4. At the bottom select **"Create a new branch and start a merge request"**
5. Submit — the CI validation pipeline starts automatically

### What Happens on MR Submission

The `validate-community-mr` job runs automatically and:
- Compiles the submitted rule using `yarac64.exe` — **MR is blocked if compilation fails**
- Clones the detection-rules-repo and checks for rule name conflicts against all rules currently in production — warns but does not block
- Posts a comment directly on the MR with pass/fail details and error messages

### Fixing a Failed MR

If your rule fails to compile, **do not create a new branch**. Edit the file on your existing branch:

1. Go to the MR page → click the file → click **Edit**
2. Fix the syntax error
3. Commit to the **same branch**
4. The CI re-runs automatically

### After Merge

Once approved and merged to main, the pipeline automatically publishes the new community rule to the detection-rules-repo. No manual steps required.

---

## Validation

### Deduplication (`validate_prod.py`)
Scans all YARA rule files across all sources for duplicate rule names. When a duplicate is found the second occurrence is automatically renamed by appending `_1`, `_2` etc. directly inside the file. Content duplicates are logged but both copies are kept.

### Compile Check (`validate_prod.py`)
Each rule bundle is compiled using `yarac64.exe` (located at `pipeline/fetchers/tools/yarac64.exe`). The pipeline fails if any bundle does not compile cleanly.

---

## Publishing

`publish_prod.py` clones the detection-rules-repo, copies validated rules into it using an additive approach (new files added, changed files updated, nothing deleted), and pushes a commit if any changes are detected. The commit message summarises what changed.

---

## CI/CD Variables

The following variables must be configured in **GitLab → Settings → CI/CD → Variables**:

| Variable | Description | Masked |
|---|---|---|
| `PAT_TOKEN` | Personal access token for publishing to detection-rules-repo | Yes |
| `APIv4_PUBLIC` | Mandiant API public key | Yes |
| `APIv4_SECRET` | Mandiant API secret key | Yes |
| `AWS_ACCESS_KEY_ID` | AWS credentials for S3 fetch | Yes |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials for S3 fetch | Yes |
| `CUSTOMER_REPO_PATH_TEST` | Path to detection-rules-repo | No |
| `user_email` | Git commit author email | No |
| `user_name` | Git commit author username | No |
| `SSL_CERT_FILE_PATH` | Path to internal SSL certificate | No |

---

## Operational Environment Sync

After rules are published to the detection-rules-repo, operational processing servers sync rules to their local Thor directories using a sparse checkout sync script. See the [Wiki](./wiki) for full documentation on the sync process.

---

## Further Reading

See the [Detection Rules Pipeline — Technical Wiki](./Detection_Rules_Pipeline_Wiki.docx) for full architecture documentation including:
- Detailed pipeline stage descriptions
- Runner host configuration
- Operational server sync process
- Thor directory structure
- Adding new rule sources
- Troubleshooting guide
