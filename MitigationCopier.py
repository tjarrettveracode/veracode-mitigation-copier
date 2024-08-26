import sys
import argparse
import logging
import json
import datetime
import os

import anticrlf
from veracode_api_py.api import VeracodeAPI as vapi, Applications, Findings, SCAApplications, Sandboxes
from veracode_api_py.constants import Constants
from veracode_api_signing.credentials import get_credentials

log = logging.getLogger(__name__)

ALLOWED_ACTIONS = ['COMMENT', 'FP', 'APPDESIGN', 'OSENV', 'NETENV', 'REJECTED', 'ACCEPTED', 'LIBRARY', 'ACCEPTRISK', 
                   'APPROVE', 'REJECT', 'BYENV', 'BYDESIGN', 'LEGAL', 'COMMERCIAL', 'EXPERIMENTAL', 'INTERNAL']

class VeracodeApiCredentials():
    api_key_id = None
    api_key_secret = None

    def __init__(self, api_key_id, api_key_secret):
        self.api_key_id = api_key_id
        self.api_key_secret = api_key_secret

    def run_with_credentials(self, to_run):
        old_id = os.environ.get('veracode_api_key_id', "")
        old_secret = os.environ.get('veracode_api_key_secret', "")
        os.environ['veracode_api_key_id'] = self.api_key_id
        os.environ['veracode_api_key_secret'] = self.api_key_secret
        try:
            return to_run(None)
        finally:
            os.environ['veracode_api_key_id'] = old_id
            os.environ['veracode_api_key_secret'] = old_secret


def setup_logger():
    handler = logging.FileHandler('MitigationCopier.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    log = logging.getLogger(__name__)
    log.addHandler(handler)
    log.setLevel(logging.INFO)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def prompt_for_app(prompt_text):
    appguid = ""
    app_name_search = input(prompt_text)
    app_candidates = Applications().get_by_name(app_name_search)
    if len(app_candidates) == 0:
        print("No matches were found!")
    elif len(app_candidates) > 1:
        print("Please choose an application:")
        for idx, appitem in enumerate(app_candidates,start=1):
            print("{}) {}".format(idx, appitem["profile"]["name"]))
        i = input("Enter number: ")
        try:
            if 0 < int(i) <= len(app_candidates):
                appguid = app_candidates[int(i)-1].get('guid')
        except ValueError:
            appguid = ""
    else:
        appguid = app_candidates[0].get('guid')

    return appguid

def get_app_guid_from_legacy_id(app_id):
    app = Applications().get(legacy_id=app_id)
    if app is None:
        return
    return app['_embedded']['applications'][0]['guid']

def get_application_name(guid):
    app = Applications().get(guid)
    return app['profile']['name']    

def get_findings_by_type(app_guid, scan_type='STATIC', sandbox_guid=None):
    findings = []
    if scan_type == 'STATIC':
        findings = Findings().get_findings(app_guid,scantype=scan_type,annot='TRUE',sandbox=sandbox_guid)
    elif scan_type == 'DYNAMIC':
        findings = Findings().get_findings(app_guid,scantype=scan_type,annot='TRUE')

    return findings

def logprint(log_msg):
    log.info(log_msg)
    print(log_msg)

def filter_approved(findings,id_list):
    if id_list is not None:
        log.info('Only copying the following findings provided in id_list: {}'.format(id_list))
        findings = [f for f in findings if f['issue_id'] in id_list]

    return [f for f in findings if (f['finding_status']['resolution_status'] == 'APPROVED')]

def format_file_path(file_path):

    # special case - omit prefix for teamcity work directories, which look like this:
    # teamcity/buildagent/work/d2a72efd0db7f7d7
    if file_path is None:
        return ''

    suffix_length = len(file_path)

    buildagent_loc = file_path.find('teamcity/buildagent/work/')

    if buildagent_loc > 0:
        #strip everything starting with this prefix plus the 17 characters after
        # (25 characters for find string, 16 character random hash value, plus / )
        formatted_file_path = file_path[(buildagent_loc + 42):suffix_length]
    else:
        formatted_file_path = file_path

    return formatted_file_path

def create_match_format_policy(app_guid, sandbox_guid, policy_findings, finding_type):
    findings = []

    if finding_type == 'STATIC':
        thesefindings = [{'app_guid': app_guid,
                'sandbox_guid': sandbox_guid,
                'id': pf['issue_id'],
                'resolution': pf['finding_status']['resolution'],
                'cwe': pf['finding_details']['cwe']['id'],
                'procedure': pf['finding_details'].get('procedure'),
                'relative_location': pf['finding_details'].get('relative_location'),
                'source_file': format_file_path(pf['finding_details'].get('file_path')),
                'line': pf['finding_details'].get('file_line_number'),
                'finding': pf} for pf in policy_findings]
        findings.extend(thesefindings)
    elif finding_type == 'DYNAMIC':
        thesefindings = [{'app_guid': app_guid,
                'id': pf['issue_id'],
                'resolution': pf['finding_status']['resolution'],
                'cwe': pf['finding_details']['cwe']['id'],
                'path': pf['finding_details']['path'],
                'vulnerable_parameter': pf['finding_details'].get('vulnerable_parameter',''), # vulnerable_parameter may not be populated for some info leak findings
                'finding': pf} for pf in policy_findings]
        findings.extend(thesefindings)
    return findings

def format_application_name(guid, app_name, sandbox_guid=None):
    if sandbox_guid is None:
        formatted_name = 'application {} (guid: {})'.format(app_name,guid)
    else:
        formatted_name = 'sandbox {} in application {} (guid: {})'.format(sandbox_guid,app_name,guid)
    return formatted_name

def submit_sca_mitigation(app_guid, action, comment, component_id, annotation_type, issue_id):
    try:
        if annotation_type == "vulnerability":
            SCAApplications().add_annotation(app_guid=app_guid, action=action, comment=comment, annotation_type="VULNERABILITY",
                                             component_id=component_id,cve_name=issue_id)
        else:
            SCAApplications().add_annotation(app_guid=app_guid, action=action, comment=comment, annotation_type="LICENSE",
                                             component_id=component_id,license_id=issue_id)
        log.info(f'Updated {annotation_type} mitigation information to {action} for component {component_id} and issue_id {issue_id} in application {app_guid}')
        return True
    except:
        log.error(f'Unable to submit {annotation_type} mitigation information to {action} for component {component_id} and issue_id {issue_id} in application {app_guid}')
    return False

def update_sca_mitigation_info_rest(app_guid, action, comment, annotation_type, component_id, issue_id, propose_only):
    # validate length of comment argument, gracefully handle overage
    if len(comment) > 2048:
        comment = comment[0:2048]

    if not action in ALLOWED_ACTIONS:
        log.warning(f'Cannot copy {action} mitigation for component {component_id} and issue_id {issue_id} in {app_guid}')
        return
    elif action == 'APPROVE':
        if propose_only:
            log.warning(f'propose_only set to True; skipping applying approval for component {component_id} and issue_id {issue_id} in {app_guid}')
            return
    
    return submit_sca_mitigation(app_guid, action, comment, component_id, annotation_type, issue_id)


def update_mitigation_info_rest(to_app_guid,flaw_id,action,comment,sandbox_guid=None, propose_only=False):
    # validate length of comment argument, gracefully handle overage
    if len(comment) > 2048:
        comment = comment[0:2048]
    if not action in ALLOWED_ACTIONS:
        log.warning('Cannot copy {} mitigation for Flaw ID {} in {}'.format(action,flaw_id,to_app_guid))
        return
    elif action == 'APPROVED':
        if propose_only:
            log.info('propose_only set to True; skipping applying approval for flaw_id {}'.format(flaw_id))
            return
        action = Constants.ANNOT_TYPE[action]
    elif action == 'CUSTOMCLEANSERPROPOSED' or action == 'CUSTOMCLEANSERUSERCOMMENT':
        log.warning(f"""Cannot copy '{action}' mitigation for Flaw ID {flaw_id} in {to_app_guid}""")
        return
    
    flaw_id_list = [flaw_id]
    try:
        if sandbox_guid==None:
            Findings().add_annotation(to_app_guid,flaw_id_list,comment,action)
        else:
            Findings().add_annotation(to_app_guid,flaw_id_list,comment,action,sandbox=sandbox_guid)
        log.info(
            'Updated mitigation information to {} for Flaw ID {} in {}'.format(action, str(flaw_id_list), to_app_guid))
    except requests.exceptions.RequestException as e:
        logprint(f"""WARNING: Unable to apply annotation '{action}' for Flaw ID {flaw_id_list} in {to_app_guid}""")
        log.exception('Ignoring request exception')

def set_in_memory_flaw_to_approved(findings_to,to_id):
    # use this function to update the status of target findings in memory, so that, if it is found
    # as a match for multiple flaws, we only copy the mitigations once.
    for finding in findings_to:
        if all (k in finding for k in ("id", "finding")):
            if (finding["id"] == to_id):
                finding['finding']['finding_status']['resolution_status'] = 'APPROVED'

def match_sca(findings_from_approved, from_app_guid, to_app_guid, dry_run, annotation_type, propose_only, from_credentials, to_credentials):
    results_from_app_name = from_credentials.run_with_credentials(lambda _: get_application_name(from_app_guid))
    formatted_from = format_application_name(from_app_guid,results_from_app_name)
    logprint('Getting SCA findings for {}'.format(formatted_from))    

    count_from = len(findings_from_approved)
    if count_from == 0:
        logprint('No approved findings in "from" {}. Exiting.'.format(formatted_from))
        return 0
    
    logprint('Found {} approved mitigations on SCA findings in {}'.format(count_from,formatted_from))
    
    results_to_app_name = to_credentials.run_with_credentials(lambda _: get_application_name(to_app_guid))
    formatted_to = format_application_name(to_app_guid,results_to_app_name)

    counter = 0
    
    for sca_finding in findings_from_approved:
        component_file_name = sca_finding['component']['filename']
        component_id = sca_finding['component']['id']
        if annotation_type == "license":
            issue_id = sca_finding['license']['license_id']
        else:
            issue_id = sca_finding['vulnerability']['cve_name']

        # might need to add some logic to skip already mitigated findings
                    
        mitigation_list = sca_finding['history']
        logprint (f'Applying {len(mitigation_list)} {annotation_type} annotations to {component_file_name} with issue id {issue_id} in {formatted_to}...')

        for mitigation_action in reversed(mitigation_list): # SCA mitigations API puts most recent action first
            proposal_action = mitigation_action['annotation_action']
            proposal_comment = f'COPIED {proposal_action} MITIGATION FROM APP {from_app_guid} AT {datetime.datetime.now()}'
            if not(dry_run):
                if not to_credentials.run_with_credentials(lambda _: update_sca_mitigation_info_rest(to_app_guid, proposal_action, proposal_comment, annotation_type, component_id, issue_id, propose_only)):
                    counter-=1
                    break

        counter += 1

    print('[*] Updated {} flaws in {}. See log file for details.'.format(str(counter),formatted_to))

def get_formatted_app_name(app_guid, sandbox_guid):
    app_name = get_application_name(app_guid)
    return format_application_name(app_guid,app_name,sandbox_guid)

def get_findings_from(from_app_guid, scan_type, from_sandbox_guid=None):
    formatted_app_name = get_formatted_app_name(from_app_guid, from_sandbox_guid)
    logprint('Getting {} findings for {}'.format(scan_type.lower(),formatted_app_name))
    findings_from = get_findings_by_type(from_app_guid,scan_type=scan_type, sandbox_guid=from_sandbox_guid)
    count_from = len(findings_from)
    logprint('Found {} {} findings in "from" {}'.format(count_from,scan_type.lower(),formatted_app_name))
    return findings_from

def match_for_scan_type(findings_from, from_app_guid, to_app_guid, dry_run, from_credentials, to_credentials, scan_type='STATIC',from_sandbox_guid=None,
        to_sandbox_guid=None, propose_only=False, id_list=[], fuzzy_match=False):
    if len(findings_from) == 0:
        return 0 # no source findings to copy!

    from_app_name = from_credentials.run_with_credentials(lambda _: get_application_name(from_app_guid))
    formatted_from = format_application_name(from_app_guid,from_app_name,from_sandbox_guid)
            
    if len(filter_approved(findings_from,id_list)) == 0:
        logprint('No approved findings in "from" {}. Exiting.'.format(formatted_from))
        return 0

    results_to_app_name = to_credentials.run_with_credentials(lambda _: get_application_name(to_app_guid))
    formatted_to = format_application_name(to_app_guid,results_to_app_name,to_sandbox_guid)

    logprint('Getting {} findings for {}'.format(scan_type.lower(),formatted_to))
    findings_to = to_credentials.run_with_credentials(lambda _: get_findings_by_type(to_app_guid,scan_type=scan_type, sandbox_guid=to_sandbox_guid))
    count_to = len(findings_to)
    logprint('Found {} {} findings in "to" {}'.format(count_to,scan_type.lower(),formatted_to))
    if count_to == 0:
        return 0 # no destination findings to mitigate!

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    copy_array_to = create_match_format_policy( app_guid=to_app_guid, sandbox_guid=to_sandbox_guid, policy_findings=findings_to,finding_type=scan_type)

    # We'll return how many mitigations we applied
    counter = 0

    formatted_from = from_credentials.run_with_credentials(lambda _: get_formatted_app_name(from_app_guid, from_sandbox_guid))
    # look for a match for each finding in the TO list and apply mitigations of the matching flaw, if found
    for this_to_finding in findings_to:
        to_id = this_to_finding['issue_id']

        if this_to_finding['finding_status']['resolution_status'] == 'APPROVED':
            logprint ('Flaw ID {} in {} already has an accepted mitigation; skipped.'.format(to_id,formatted_to))
            continue

        match = Findings().match(this_to_finding,findings_from,approved_matches_only=True,allow_fuzzy_match=fuzzy_match)

        if match == None:
            log.info('No approved match found for finding {} in {}'.format(to_id,formatted_from))
            continue

        from_id = match.get('id')

        log.info('Source flaw {} in {} has a possible target match in flaw {} in {}.'.format(from_id,formatted_from,to_id,formatted_to))

        mitigation_list = match['finding']['annotations']
        logprint ('Applying {} annotations for flaw ID {} in {}...'.format(len(mitigation_list),to_id,formatted_to))

        for mitigation_action in reversed(mitigation_list): #findings API puts most recent action first
            proposal_action = mitigation_action['action']
            proposal_comment = '(COPIED FROM APP {}) {}'.format(from_app_guid, mitigation_action['comment'])
            if not(dry_run):
                to_credentials.run_with_credentials(lambda _: update_mitigation_info_rest(to_app_guid, to_id, proposal_action, proposal_comment, to_sandbox_guid, propose_only))

        set_in_memory_flaw_to_approved(copy_array_to,to_id) # so we don't attempt to mitigate approved finding twice
        counter += 1

    print('[*] Updated {} flaws in {}. See log file for details.'.format(str(counter),formatted_to))

def get_exact_sandbox_name_match(sandbox_name, sandbox_candidates):
    for sandbox_candidate in sandbox_candidates:
        if sandbox_candidate["name"] == sandbox_name:
            return sandbox_candidate["guid"]
    print("Unable to find sandbox named " + sandbox_name)
    return None

def get_sandbox_by_name(application_id, sandbox_name):
    sandbox_candidates = Sandboxes().get_all(application_id)
    if len(sandbox_candidates) == 0:
        print("No sandboxes found for application " + application_id)
        return None
    else:
        return get_exact_sandbox_name_match(sandbox_name, sandbox_candidates)

def get_sandbox_guids_by_name(results_to_app_ids, results_to_sandbox_names):
    sandbox_ids = []
    names_as_list = [sandbox.strip() for sandbox in results_to_sandbox_names.split(", ")]

    for index, sandbox_name in enumerate(names_as_list):
        sandbox_id = get_sandbox_by_name(results_to_app_ids[index], sandbox_name)
        if sandbox_id is not None:
            sandbox_ids.append(sandbox_id)

    return sandbox_ids

def get_exact_application_name_match(application_name, app_candidates):
    for application_candidate in app_candidates:
        if application_candidate["profile"]["name"] == application_name:
            return application_candidate["guid"]
    print("Unable to find application named " + application_name)
    return None

def get_application_by_name(application_name):
    app_candidates = Applications().get_by_name(application_name)
    if len(app_candidates) == 0:
        print("Unable to find application named " + application_name)
        return None
    elif len(app_candidates) > 1:
        return get_exact_application_name_match(application_name, app_candidates)
    else:
        return app_candidates[0].get('guid')

def get_application_guids_by_name(application_names):
    application_ids = []
    names_as_list = [application.strip() for application in application_names.split(", ")]

    for application_name in names_as_list:
        application_id = get_application_by_name(application_name)
        if application_id is not None:
            application_ids.append(application_id)

    return application_ids

def get_sca_findings_for(from_app_guid, annotation_type):
    findings_from_approved = SCAApplications().get_annotations(app_guid=from_app_guid, annotation_type=annotation_type.upper())
    if findings_from_approved:
        return findings_from_approved['approved_annotations']
    return []

def main():
    parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM APP. For any flaws that have an '
                    'accepted mitigation, it checks the TO APP to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
    parser.add_argument('-f', '--fromapp', help='App GUID to copy from')
    parser.add_argument('-fs', '--fromsandbox', help='Sandbox GUID to copy from (optional)')
    parser.add_argument('-t', '--toapp', help='App GUID to copy to')
    parser.add_argument('-ts', '--tosandbox', help="Sandbox GUID to copy to (optional)")

    parser.add_argument('-fn', '--fromappname', help='Application Name to copy from')
    parser.add_argument('-fsn', '--fromsandboxname', help='Sandbox Name to copy from')

    parser.add_argument('-tn', '--toappnames', help='Comma-delimited list of Application Names to copy to')
    parser.add_argument('-tsn', '--tosandboxnames', help='Comma-delimited list of Sandbox Names to copy to - should be in the same order as --toappnames')

    parser.add_argument('-st','--scan_types', help='Comma-delimited list of scan types to copy mitigations (default: SAST, DAST)')
    parser.add_argument('-sit','--sca_import_type', help='Comma-delimited list of types of SCA issues to import (default: licenses, vulnerabilities)')

    parser.add_argument('-p', '--prompt', action='store_true', help='Specify to prompt for the applications to copy from and to.')
    parser.add_argument('-d', '--dry_run', action='store_true', help="Log matched flaws instead of applying mitigations")
    parser.add_argument('-l', '--legacy_ids',action='store_true', help='Use legacy Veracode app IDs instead of GUIDs')
    parser.add_argument('-po', '--propose_only',action='store_true', help='Only propose mitigations, do not approve them')
    parser.add_argument('-i','--id_list',nargs='*', help='Only copy mitigations for the flaws in the id_list')
    parser.add_argument('-fm','--fuzzy_match',action='store_true', help='Look within a range of line numbers for a matching flaw')

    parser.add_argument('-vid','--veracode_api_key_id', help='VERACODE_API_KEY_ID to use (if combined with --to_veracode_api_key_id and --to_veracode_api_key_secret, allows for moving mitigations between different instances of the platform)')
    parser.add_argument('-vkey','--veracode_api_key_secret', help='VERACODE_API_KEY_SECRET to use (if combined with --to_veracode_api_key_id and --to_veracode_api_key_secret, allows for moving mitigations between different instances of the platform)')

    parser.add_argument('-tid','--to_veracode_api_key_id', help='VERACODE_API_KEY_ID to use for TO apps/sandboxes (allows for moving mitigations between different instances of the platform)')
    parser.add_argument('-tkey','--to_veracode_api_key_secret', help='VERACODE_API_KEY_SECRET to use for TO apps/sandboxes (allows for moving mitigations between different instances of the platform)')

    args = parser.parse_args()

    setup_logger()

    logprint('======== beginning MitigationCopier.py run ========')

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # SET VARIABLES FOR FROM AND TO APPS
    results_from_app_id = args.fromapp
    results_to_app_ids = [args.toapp]
    results_from_sandbox_id = args.fromsandbox
    results_to_sandbox_ids = args.tosandbox

    results_from_app_name = args.fromappname
    results_from_sandbox_name = args.fromsandboxname
    results_to_app_names = args.toappnames
    results_to_sandbox_names = args.tosandboxnames
    scan_types = args.scan_types
    sca_import_type = args.sca_import_type

    prompt = args.prompt
    dry_run = args.dry_run
    legacy_ids = args.legacy_ids
    propose_only = args.propose_only
    id_list = args.id_list
    fuzzy_match = args.fuzzy_match
    
    from_credentials = None
    to_credentials = None

    if args.veracode_api_key_id and args.veracode_api_key_secret:
        from_credentials = VeracodeApiCredentials(args.veracode_api_key_id, args.veracode_api_key_secret)
    else:
        api_key_id, api_key_secret = get_credentials()
        from_credentials = VeracodeApiCredentials(api_key_id, api_key_secret)
    
    if args.to_veracode_api_key_id and args.to_veracode_api_key_secret:
        to_credentials = VeracodeApiCredentials(args.to_veracode_api_key_id, args.to_veracode_api_key_secret)
    elif from_credentials:
        to_credentials = from_credentials


    if prompt:
        results_from_app_id = from_credentials.run_with_credentials(lambda _:  prompt_for_app("Enter the application name to copy mitigations from: "))
        results_to_app_ids = to_credentials.run_with_credentials(lambda _: [prompt_for_app("Enter the application name to copy mitigations to: ")])
        # ignore Sandbox arguments in the Prompt case
        results_from_sandbox_id = None
        results_to_sandbox_ids = None
    else:
        if results_from_app_name:
            results_from_app_id = from_credentials.run_with_credentials(lambda _: get_application_guids_by_name(results_from_app_name)[0])
        if results_from_sandbox_name:
            results_from_sandbox_id = from_credentials.run_with_credentials(lambda _: get_sandbox_guids_by_name([results_from_app_id], results_from_sandbox_name)[0])
        if results_to_app_names:
            results_to_app_ids = to_credentials.run_with_credentials(lambda _: get_application_guids_by_name(results_to_app_names))
        if results_to_sandbox_names:
            results_to_sandbox_ids = to_credentials.run_with_credentials(lambda _: get_sandbox_guids_by_name(results_to_app_ids, results_to_sandbox_names))

    is_sast = False
    is_dast = False
    is_sca = False
    is_sca_vulnerabilities = False
    is_sca_licences = False
    if scan_types:
        scan_types = scan_types.lower()
        is_sast = 'sast' in scan_types
        is_dast = 'dast' in scan_types
        is_sca = 'sca' in scan_types
        if is_sca:
            if sca_import_type:
                sca_import_type = sca_import_type.lower()
                is_sca_vulnerabilities = 'vulnerabilit' in sca_import_type
                is_sca_licences = 'license' in sca_import_type
            else:
                is_sca_vulnerabilities = True
                is_sca_licences = True
        if not is_dast and not is_sast and not is_sca_licences and not is_sca_licences:
            print('No valid scan types were provided.')
            print('Valid scan_types are: DAST, SAST, SCA.')
            print('Valid sca_import_type are: licenses, vulnerabilities.')
            return        
    else:
        is_sast = True
        is_dast = True

    if results_from_app_id in ( None, '' ) or results_to_app_ids in ( None, '' ):
        print('You must provide an application to copy mitigations to and from.')
        return

    if legacy_ids:
        results_from = from_credentials.run_with_credentials(lambda _: get_app_guid_from_legacy_id(results_from_app_id))
        results_to = to_credentials.run_with_credentials(lambda _: get_app_guid_from_legacy_id(results_to_app_ids))
        results_from_app_id = results_from
        results_to_app_ids = results_to

    # get static findings and apply mitigations
    if is_sast:
        all_static_findings = from_credentials.run_with_credentials(lambda _: get_findings_from(from_app_guid=results_from_app_id, scan_type='STATIC',
            from_sandbox_guid=results_from_sandbox_id))
    if is_dast:
        all_dynamic_findings = from_credentials.run_with_credentials(lambda _: get_findings_from(from_app_guid=results_from_app_id, scan_type='DYNAMIC',
            from_sandbox_guid=results_from_sandbox_id))
    if is_sca_vulnerabilities:
        all_sca_vulnerabilities = from_credentials.run_with_credentials(lambda _: get_sca_findings_for(from_app_guid=results_from_app_id, annotation_type="vulnerability"))
    if is_sca_licences:
        all_sca_licenses = from_credentials.run_with_credentials(lambda _: get_sca_findings_for(from_app_guid=results_from_app_id, annotation_type="license"))

    for index, to_app_id in enumerate(results_to_app_ids):
        if is_sast:
            match_for_scan_type(all_static_findings, from_app_guid=results_from_app_id, to_app_guid=to_app_id, dry_run=dry_run, scan_type='STATIC',
                from_sandbox_guid=results_from_sandbox_id,to_sandbox_guid=results_to_sandbox_ids[index] if results_to_sandbox_ids else None,propose_only=propose_only,id_list=id_list,fuzzy_match=fuzzy_match, from_credentials=from_credentials, to_credentials=to_credentials)
        if is_dast:
            match_for_scan_type(all_dynamic_findings, from_app_guid=results_from_app_id, to_app_guid=to_app_id, dry_run=dry_run,
                scan_type='DYNAMIC',propose_only=propose_only,id_list=id_list, from_credentials=from_credentials, to_credentials=to_credentials)
        if is_sca_vulnerabilities:
            match_sca(all_sca_vulnerabilities, from_app_guid=results_from_app_id, to_app_guid=to_app_id, dry_run=dry_run,annotation_type="vulnerability",propose_only=propose_only, from_credentials=from_credentials, to_credentials=to_credentials)
        if is_sca_licences:
            match_sca(all_sca_licenses, from_app_guid=results_from_app_id, to_app_guid=to_app_id, dry_run=dry_run,annotation_type="license",propose_only=propose_only, from_credentials=from_credentials, to_credentials=to_credentials)

if __name__ == '__main__':
    main()
