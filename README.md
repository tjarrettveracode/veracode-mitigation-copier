# Veracode Mitigation Copier

Copies mitigations from one Veracode profile to another if it's the same flaw based on the following flaw attributes:

- **Static**: `cweid`, `type`, `sourcefile`, and `line` (see Note 1 below)
- **Static (no debug information)**: `cweid`, `type`, `procedure` and `relative_location`
- **Dynamic**: `cweid`, `path` and `vulnerable_parameter`

The script will copy all accepted mitigations for the flaw. The script will skip a flaw in the `copy_to` build if it already has an accepted mitigation.

*Note*: This script requires Python 3!

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-mitigation-copier

Install dependencies:

    cd veracode-mitigation-copier
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python MitigationCopier.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python MitigationCopier.py (arguments)

Arguments supported include:

- `-f`, `--fromapp` - Application GUID that you want to copy mitigations from.
- `-fn`, `--fromappname` - (optional) - Application Name that you want to copy mitigations from. Overrides `--fromapp`.
- `-fs`, `--fromsandbox` (optional) - Sandbox GUID that you want to copy mitigations from. Ignored if `--prompt` is set.
- `-t`, `--toapp` - Application GUID that you want to copy mitigations to.
- `-tn`, `--toappnames` - (optional) - Comma-delimited list of Application Names to copy mitigations to. Overrides `--toapp`.
- `-ts`, `--tosandbox` (optional) - Sandbox GUID that you want to copy mitigations to. Ignored if `--prompt` is set.
- `-p`, `--prompt` - Specify to prompt for the applications to copy from and to.
- `-d`, `--dry_run` (optional) - Specify to log potential copied mitigations rather than actually mitigating the findings.
- `-l`, `--legacy_ids` (optional) - Specify to use legacy Veracode application IDs rather than application GUIDs.
- `-po`, `--propose-only` (optional) - If specified, only propose mitigations; do not approve the copied mitigations.
- `-i`, `--id_list` (optional) - If specified, only copy mitigations from the `fromapp` for the flaw IDs in `id_list`.

## Logging

The script creates a `MitigationCopier.log` file. All actions are logged.

## Usage examples

### Copy from one application profile to a list of application profiles
    python MitigationCopier.py -fn "Origin App Name" -tn "Target App 1, Target App 2, Target App 3"

### Copy from one application profile to another with prompts

    python MitigationCopier.py --prompt

### Copy from one application profile to another, specifying the profiles

    python MitigationCopier.py --fromapp abcdefgh-1234-abcd-1234-123456789012 --toapp 12345678-abcd-1234-abcd-abcdefghijkl

### Copy mitigations for a subset of findings

    python MitigationCopier.py --fromapp abcdefgh-1234-abcd-1234-123456789012 --toapp 12345678-abcd-1234-abcd-abcdefghijkl --id_list 1 2 3

You must provide the application GUID values for both application profiles. You can look these up by calling the [Veracode Applications API](https://help.veracode.com/r/c_apps_intro) (or use the `--prompt` argument and copy the GUIDs from the console output).

### Copy from one application profile to another, specifying the profiles with legacy IDs

    python MitigationCopier.py --fromapp 1234567 --toapp 7654321

You must provide the legacy Veracode application ID values for both application profiles. These IDs are available from the Veracode XML APIs.

### See which findings are affected in a target profile, but don't copy the mitigations

    python MitigationCopier.py --prompt --dry_run

## Notes

1. For static findings, when matching by line number, we automatically look within a range of line numbers around the original finding line number to allow for drift. This is controlled by the constant `LINE_NUMBER_SLOP` declared at the top of the file.
2. For static findings when source file information is not available, we try to use procedure and relative location. This is less predictable so it is recommended that you perform a dry run when copying mitigations from non-debug code. Unlike when source file information is available, we do not use "sloppy matching" in this case -- we have observed that mitigations in non-debug code are most common when a binary dependency is being reused across teams and thus locations are less likely to change.
