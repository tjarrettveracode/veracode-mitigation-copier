# Veracode Mitigation Copier

## Required Libraries

`veracode-api-py`, `requests`, and `logging-formatter-anticrlf`, which can be installed using `pip` (or `pip3`):

    pip install -r requirements.txt

## Description

Copies mitigations from one Veracode profile to another if it's the same flaw based on the following flaw attributes:

- **Static**: `cweid`, `type`, `sourcefile`, and `line`
- **Dynamic**: `cweid`, `path` and `vulnerable_parameter`

The script will copy all proposed and accepted mitigations for the flaw. The script will skip a flaw in the `copy_to` build if it already has an accepted mitigation.

API credentials are supplied using the [standard Veracode methods](https://help.veracode.com/go/c_configure_api_cred_file) (either via a `.veracode/credentials` file or via environment variables).

## Parameters

1. `-f`, `--fromapp` - Application GUID that you want to copy mitigations from.
1. `-fs`, `--fromsandbox` (optional) - Sandbox GUID that you want to copy mitigations from.
1. `-t`, `--toapp` - Application GUID that you want to copy mitigations to.
1. `-ts`, `--tosandbox` (optional) - Sandbox GUID that you want to copy mitigations to.
1. `-p`, `--prompt` - Specify to prompt for the applications to copy from and to.
1. `-d`, `--dry_run` (optional) - Specify to log potential copied mitigations rather than actually mitigating the findings.

## Logging

The script creates a `MitigationCopier.log` file. All actions are logged.
