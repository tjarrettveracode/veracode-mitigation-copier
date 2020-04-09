# Veracode Mitigation Copier

## Required Libraries
`veracode-api-signing`, `requests`, and `lxml`, which can be installed using pip:

    pip install -r requirements.txt

## Description
Copies mitigations from one Veracode profile to another if it's the same flaw based on the following flaw attributes: `issueid`, `cweid`, `type`, `sourcefile`, and `line`. The script will copy all proposed and accepted mitigations for the flaw. The script will skip a flaw in the `copy_to` build if it already has an accepted mitigation.

## Parameters
    1. -f, --frombuild  # Build ID that you want to copy mitigations from.
    2. -t, --tobuild  # Build ID that you want to copy mitigations to.
    3. -v, --vid  # Veracode API credentials ID.
    4. -k, --vkey  # Veracode API credentials key.

## Logging
The script creates a `MitigationCopier.log` file. All actions are logged.
