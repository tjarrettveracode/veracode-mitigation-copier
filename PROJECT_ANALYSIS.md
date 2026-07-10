# Veracode Mitigation Copier - Project Analysis

## Overview

**Veracode Mitigation Copier** is a Python utility that automates the process of copying security mitigations from one Veracode application profile to another. It matches findings across profiles and replicates approved mitigations, streamlining security management across multiple applications or builds.

### Purpose

The primary use case is reducing manual work when:
- Managing multiple applications with similar codebases or dependencies
- Propagating security decisions (mitigations, false positive declarations, etc.) across build variants or environments
- Migrating mitigations between different Veracode instances
- Bulk-approving findings that match across multiple scans

## Architecture

### Dependencies

- **veracode-api-py** (≥0.9.46): Official Python SDK for Veracode APIs
  - Provides access to Applications, Findings, SCAApplications, and Sandboxes endpoints
  - Handles API credential management
- **logging-formatter-anticrlf** (≥1.2): Sanitizes log output to prevent log injection attacks

### Key Components

#### 1. **Credential Management** (`VeracodeApiCredentials` class)

- Encapsulates API credential handling for both "from" and "to" applications
- Temporarily sets environment variables for credential isolation
- Supports cross-instance operations (different Veracode accounts/regions)
- Credentials sourced from:
  1. Command-line arguments (`--veracode_api_key_id`, `--veracode_api_key_secret`)
  2. Environment variables (`VERACODE_API_KEY_ID`, `VERACODE_API_KEY_SECRET`)
  3. Credentials file (`~/.veracode/credentials`)

#### 2. **Finding Retrieval & Matching**

**Static Findings (SAST):** Matched on:
- CWE ID (Common Weakness Enumeration)
- Issue type
- Source file path
- Line number (with configurable slop for drift tolerance)

**Alternative (no debug info):** Matched on:
- CWE ID
- Issue type
- Procedure name
- Relative location

**Dynamic Findings (DAST):** Matched on:
- CWE ID
- API endpoint path
- Vulnerable parameter

**SCA Findings:** Matched by:
- Component ID (for vulnerabilities and licenses)
- CVE name or license ID

#### 3. **Mitigation Application**

The script supports multiple mitigation actions defined in `ALLOWED_ACTIONS`:
- `COMMENT`: Add a comment without changing status
- `FP` (False Positive)
- `APPDESIGN`, `OSENV`, `NETENV`: Environmental mitigations
- `ACCEPTRISK`: Accept and document risk
- `APPROVED`: Accept the mitigation
- `LIBRARY`, `LEGAL`, `COMMERCIAL`, `INTERNAL`, `EXPERIMENTAL`: Business justifications
- And others (REJECT, etc.)

---

## Script Logic Flow

### Initialization Phase

```
1. Parse command-line arguments
2. Set up logging to dated log file in mitigation_copier_logs/ directory
3. Check API credential expiration (warn if < 7 days remaining)
4. Load credentials (from CLI args, environment, or credentials file)
```

### Application Resolution Phase

Supports three modes:

**A. Interactive Mode (`--prompt`)**
- Prompts user to search for and select applications by name
- Ignores sandbox arguments

**B. By Name Mode (`--fromappname`, `--toappnames`)**
- Searches for applications by exact name match
- Supports comma-delimited target application lists
- Optional sandbox names via `--fromsandboxname` and `--tosandboxnames`

**C. By GUID/Legacy ID Mode (`--fromapp`, `--toapp`)**
- Direct GUID specification
- Optional legacy ID conversion with `--legacy_ids` flag
- Optional sandbox GUIDs via `--fromsandbox`, `--tosandbox`

### Scan Type Resolution Phase

```
Determines which scan types to process:
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)  
- SCA (Software Composition Analysis) with sub-types:
  - Vulnerabilities
  - Licenses

Default: SAST + DAST
```

### Finding Retrieval Phase

For each enabled scan type, the script:

1. **Retrieves source findings** from the "from" application/sandbox
2. **Filters approved mitigations** based on:
   - `--include_proposed` flag (to include PROPOSED status)
   - `--id_list` (whitelist of specific finding IDs to copy)
   - `--skip_id_list` (blacklist of finding IDs to skip)

```python
# Approved findings only:
findings = [f for f in findings if f['finding_status']['resolution_status'] == 'APPROVED']

# Or with proposed included:
findings = [f for f in findings if f['finding_status']['resolution_status'] in ['APPROVED', 'PROPOSED']]
```

3. **Retrieves all findings** from the target application/sandbox for matching

### Matching & Mitigation Application Phase

For each target finding that doesn't already have an approved mitigation:

1. **Find matching source finding** using the Veracode API's `match()` function
   - Supports fuzzy matching (line number range tolerance) with `--fuzzy_match`
   - Includes both approved AND proposed mitigations if `--include_proposed` is set

2. **Extract mitigation history** from the matched source finding
   - For STATIC/DYNAMIC: From `finding['annotations']` array (reversed to apply in chronological order)
   - For SCA: From `finding['history']` array (also reversed)

3. **Build mitigation comment** with optional metadata:
   - Base format: `(COPIED FROM {source_app}) {original_comment}`
   - With `--include_profile_name`: Shows application name instead of GUID
   - With `--include_original_user`: Appends original submitter/approver name

4. **Submit mitigation** to target finding:
   - For STATIC/DYNAMIC: Call `Findings().add_annotation()`
   - For SCA: Call `SCAApplications().add_annotation()`
   - Respects `--propose_only` flag: if set, only proposes (doesn't approve)

5. **Update in-memory state** to prevent duplicate copies if same finding matches multiple sources

### Multi-Target Handling

When copying to multiple applications (`--toappnames` with comma-delimited list):
- Iterates through each target application
- Applies the same mitigation matching logic independently
- Maintains separate match/copy counts for each target

### Dry Run Mode

When `--dry_run` is specified:
- Performs all matching logic
- Logs what WOULD be copied
- **Does not actually submit** mitigations to the API
- Useful for validation before large-scale copy operations

---

## Key Functions

### `logprint(log_msg)`
Dual-output utility that logs to file AND prints to console simultaneously.

### `get_findings_by_type(app_guid, scan_type, sandbox_guid)`
Retrieves all findings for an application with annotations enabled.
- `STATIC`: Includes all SAST findings
- `DYNAMIC`: Includes all DAST findings

### `filter_approved(findings, id_list, skip_id_list)`
Returns only findings with `resolution_status == 'APPROVED'`.
- Optionally filters to specific IDs or excludes specific IDs

### `filter_proposed(findings, id_list, skip_id_list)`
Returns only findings with `resolution_status == 'PROPOSED'`.

### `create_match_format_policy(app_guid, sandbox_guid, policy_findings, finding_type)`
Transforms raw API findings into normalized matching format:
- STATIC: Extracts CWE, file path, line number, procedure, relative location
- DYNAMIC: Extracts CWE, path, vulnerable parameter

### `format_file_path(file_path)`
Normalizes file paths by stripping TeamCity build agent prefixes.
- Special case: `teamcity/buildagent/work/{random_hash}/...` → `...` (removes build-specific prefix)

### `match_for_scan_type(findings_from, from_app_guid, to_app_guid, ...)`
Core matching engine for STATIC/DYNAMIC findings:

**Process:**
1. Filters source findings (approved/proposed)
2. Retrieves target findings
3. Iterates target findings, skipping those already approved/proposed
4. Calls `Findings().match()` to find corresponding source finding
5. For each match, applies all annotations from source (in chronological order)
6. Tracks successful copies in `counter`

### `match_sca(findings_from_approved, from_app_guid, to_app_guid, ...)`
Parallel logic for SCA findings:
- Iterates through approved SCA findings from source
- Identifies component ID and issue ID (CVE or license)
- Applies each historical mitigation action

### `update_mitigation_info_rest(to_app_guid, flaw_id, action, comment, ...)`
Submits a single mitigation to a STATIC/DYNAMIC finding:
- Validates action against `ALLOWED_ACTIONS`
- Truncates comments to 2048 chars
- Handles `--propose_only` mode (skips APPROVED actions)
- Converts `APPROVED` action to internal constant if needed

### `update_sca_mitigation_info_rest(app_guid, action, comment, annotation_type, ...)`
Submits a single mitigation to an SCA finding:
- Similar validation and truncation as STATIC/DYNAMIC
- Distinguishes vulnerability vs. license annotations

### `get_application_guids_by_name(application_names)`
Resolves comma-delimited application names to GUIDs:
- Splits on ", " (comma-space)
- Calls `get_application_by_name()` for each
- Returns list of resolved GUIDs

---

## Usage Examples

### Basic Copy Between Two Applications
```bash
python MitigationCopier.py \
  --fromapp abcd-1234-5678-9012 \
  --toapp efgh-1234-5678-9012
```

### Copy Between Applications by Name
```bash
python MitigationCopier.py \
  --fromappname "Production App" \
  --toappnames "Staging App, Dev App"
```

### Dry Run to Validate Matches
```bash
python MitigationCopier.py \
  --fromapp abc... \
  --toapp def... \
  --dry_run
```

### Copy Subset of Findings
```bash
python MitigationCopier.py \
  --fromapp abc... \
  --toapp def... \
  --id_list 12345 67890 11111
```

### Cross-Instance Copy
```bash
python MitigationCopier.py \
  --fromapp abc... \
  --toapp def... \
  --veracode_api_key_id <FROM_KEY_ID> \
  --veracode_api_key_secret <FROM_KEY_SECRET> \
  --to_veracode_api_key_id <TO_KEY_ID> \
  --to_veracode_api_key_secret <TO_KEY_SECRET>
```

### Include Rich Metadata
```bash
python MitigationCopier.py \
  --fromapp abc... \
  --toapp def... \
  --include_original_user \
  --include_profile_name \
  --include_proposed
```

---

## Output & Logging

### Log File Location
- Path: `mitigation_copier_logs/MitigationCopier.py_script{YYYY-MM-DD}.log`
- Format: `{timestamp} - {level} - {function_name} - {message}`
- Sanitized with anti-CRLF formatting to prevent log injection

### Key Log Messages

- Credential expiration warnings (if < 7 days)
- Application and findings retrieval counts
- Match results for each finding (matched or skipped)
- Mitigation application confirmations
- Final summary: `[*] Matched X flaws in {app}. See log file for details.`

### Console Output
- Non-log status messages mirror to console via `logprint()`
- Log file location printed at startup
- Interactive prompts for `--prompt` mode

---

## Error Handling & Edge Cases

### Credential Expiration
Warns if API credentials expire within 7 days but continues execution.

### No Matches Found
- Returns 0 from matching functions
- Logs reason (no approved findings in source, no findings in target, etc.)
- Does not fail; continues processing other applications

### Already-Approved Findings
Skips target findings that already have an approved mitigation to prevent duplicate/conflicting approvals.

### Comment Length
Truncates mitigation comments to 2,048 characters (API limit) with no error.

### Sandbox Handling
- Optional for both source and target
- Ignored if `--prompt` mode is used
- If specified, narrows finding set to that sandbox only

### Legacy ID Conversion
- If `--legacy_ids` flag is set, converts legacy app IDs to GUIDs before processing
- Fails gracefully if ID not found (returns None, early exit)

---

## Configuration & Customization

### Hardcoded Constants

- **`LOCAL_PATH`**: Log directory (default: `mitigation_copier_logs/`)
- **`ALLOWED_ACTIONS`**: List of valid mitigation action types
- **`LINE_NUMBER_SLOP`**: (Referenced in README; controls fuzzy match tolerance, may be in veracode-api-py)

### Environment Variables (Optional)

- `veracode_api_key_id`: API key ID (can be overridden by CLI args)
- `veracode_api_key_secret`: API key secret (can be overridden by CLI args)

---

## Workflow Summary

```
┌─ Parse arguments & setup logging
├─ Load credentials
├─ Resolve application GUIDs (from name/legacy ID/prompt)
├─ Resolve sandbox GUIDs (optional)
├─ For each enabled scan type (SAST, DAST, SCA):
│  ├─ Retrieve & filter source findings (approved ± proposed)
│  └─ For each target application:
│     ├─ Retrieve target findings
│     ├─ For each target finding without approved mitigation:
│     │  ├─ Match to source finding
│     │  ├─ Extract mitigation history
│     │  └─ Submit each historical mitigation (unless --dry_run)
│     └─ Log summary
└─ Exit
```

---

## Recent Changes

Based on git history:
- **d3a2971**: Converted logging to use `logprint()` function (dual console + file)
- **3f447e3**: Added `--include_proposed` switch documentation
- **37b7cf1**: Implemented `--include_proposed` flag and conditional logic for proposed findings
- **3cf560e**: Added ability to copy proposed mitigations (not just approved)

---

## Potential Enhancements

1. **Partial Failure Handling**: Currently stops at first failed mitigation for a finding; could continue to next finding
2. **Batch Metrics**: Track and report success/failure counts per action type
3. **Idempotency**: Detect already-copied mitigations to allow safe re-runs
4. **Parallel Processing**: Currently sequential; could parallelize target app processing
5. **CSV Export**: Generate report of matched/unmatched findings for audit trail
