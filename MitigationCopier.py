import sys
import argparse
import logging
import json
import datetime

import anticrlf
from veracode_api_py.api import VeracodeAPI as vapi, Applications, Findings
from veracode_api_py.constants import Constants

log = logging.getLogger(__name__)

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

def update_mitigation_info_rest(to_app_guid,flaw_id,action,comment,sandbox_guid=None, propose_only=False):
    # validate length of comment argument, gracefully handle overage
    if len(comment) > 2048:
        comment = comment[0:2048]

    if action == 'CONFORMS' or action == 'DEVIATES':
        log.warning('Cannot copy {} mitigation for Flaw ID {} in {}'.format(action,flaw_id,to_app_guid))
        return
    elif action == 'APPROVED':
        if propose_only:
            log.info('propose_only set to True; skipping applying approval for flaw_id {}'.format(flaw_id))
            return
        action = Constants.ANNOT_TYPE[action]
    flaw_id_list = [flaw_id]
    if sandbox_guid==None:
        Findings().add_annotation(to_app_guid,flaw_id_list,comment,action)
    else:
        Findings().add_annotation(to_app_guid,flaw_id_list,comment,action,sandbox=sandbox_guid)
    log.info(
        'Updated mitigation information to {} for Flaw ID {} in {}'.format(action, str(flaw_id_list), to_app_guid))

def set_in_memory_flaw_to_approved(findings_to,to_id):
    # use this function to update the status of target findings in memory, so that, if it is found
    # as a match for multiple flaws, we only copy the mitigations once.
    for finding in findings_to:
        if all (k in finding for k in ("id", "finding")):
            if (finding["id"] == to_id):
                finding['finding']['finding_status']['resolution_status'] = 'APPROVED'

def match_for_scan_type(from_app_guid, to_app_guid, dry_run, scan_type='STATIC',from_sandbox_guid=None, 
        to_sandbox_guid=None, propose_only=False, id_list=[], fuzzy_match=False):
    results_from_app_name = get_application_name(from_app_guid)
    formatted_from = format_application_name(from_app_guid,results_from_app_name,from_sandbox_guid)
    logprint('Getting {} findings for {}'.format(scan_type.lower(),formatted_from))
    findings_from = get_findings_by_type(from_app_guid,scan_type=scan_type, sandbox_guid=from_sandbox_guid)
    count_from = len(findings_from)
    logprint('Found {} {} findings in "from" {}'.format(count_from,scan_type.lower(),formatted_from))
    if count_from == 0:
        return 0 # no source findings to copy!   
   
    findings_from_approved = filter_approved(findings_from,id_list)

    if len(findings_from_approved) == 0:
        logprint('No approved findings in "from" {}. Exiting.'.format(formatted_from))
        return 0

    results_to_app_name = get_application_name(to_app_guid)
    formatted_to = format_application_name(to_app_guid,results_to_app_name,to_sandbox_guid)

    logprint('Getting {} findings for {}'.format(scan_type.lower(),formatted_to))
    findings_to = get_findings_by_type(to_app_guid,scan_type=scan_type, sandbox_guid=to_sandbox_guid)
    count_to = len(findings_to)
    logprint('Found {} {} findings in "to" {}'.format(count_to,scan_type.lower(),formatted_to))
    if count_to == 0:
        return 0 # no destination findings to mitigate!

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    copy_array_to = create_match_format_policy( app_guid=to_app_guid, sandbox_guid=to_sandbox_guid, policy_findings=findings_to,finding_type=scan_type)
    
    # We'll return how many mitigations we applied
    counter = 0

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
            proposal_comment = '[COPIED FROM APP {}] {}'.format(from_app_guid, mitigation_action['comment'])
            if not(dry_run):
                update_mitigation_info_rest(to_app_guid, to_id, proposal_action, proposal_comment, to_sandbox_guid, propose_only)

        set_in_memory_flaw_to_approved(copy_array_to,to_id) # so we don't attempt to mitigate approved finding twice
        counter += 1

    print('[*] Updated {} flaws in {}. See log file for details.'.format(str(counter),formatted_to))

def main():
    parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM APP. For any flaws that have an '
                    'accepted mitigation, it checks the TO APP to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
    parser.add_argument('-f', '--fromapp', help='App GUID to copy from')
    parser.add_argument('-fs', '--fromsandbox', help='Sandbox GUID to copy from (optional)')
    parser.add_argument('-t', '--toapp', help='App GUID to copy to')
    parser.add_argument('-ts', '--tosandbox', help="Sandbox GUID to copy to (optional)")
    parser.add_argument('-p', '--prompt', action='store_true', help='Specify to prompt for the applications to copy from and to.')
    parser.add_argument('-d', '--dry_run', action='store_true', help="Log matched flaws instead of applying mitigations")
    parser.add_argument('-l', '--legacy_ids',action='store_true', help='Use legacy Veracode app IDs instead of GUIDs')
    parser.add_argument('-po', '--propose_only',action='store_true', help='Only propose mitigations, do not approve them')
    parser.add_argument('-i','--id_list',nargs='*', help='Only copy mitigations for the flaws in the id_list')
    parser.add_argument('-fm','--fuzzy_match',action='store_true', help='Look within a range of line numbers for a matching flaw')
    args = parser.parse_args()

    setup_logger()

    logprint('======== beginning MitigationCopier.py run ========')

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # SET VARIABLES FOR FROM AND TO APPS
    results_from_app_id = args.fromapp
    results_to_app_id = args.toapp
    results_from_sandbox_id = args.fromsandbox
    results_to_sandbox_id = args.tosandbox
    prompt = args.prompt
    dry_run = args.dry_run
    legacy_ids = args.legacy_ids
    propose_only = args.propose_only
    id_list = args.id_list
    fuzzy_match = args.fuzzy_match

    if prompt:
        results_from_app_id = prompt_for_app("Enter the application name to copy mitigations from: ")
        results_to_app_id = prompt_for_app("Enter the application name to copy mitigations to: ")
        # ignore Sandbox arguments in the Prompt case
        results_from_sandbox_id = None
        results_to_sandbox_id = None

    if results_from_app_id in ( None, '' ) or results_to_app_id in ( None, '' ):
        print('You must provide an application to copy mitigations to and from.')
        return

    if legacy_ids:
        results_from = get_app_guid_from_legacy_id(results_from_app_id)
        results_to = get_app_guid_from_legacy_id(results_to_app_id)
        results_from_app_id = results_from
        results_to_app_id = results_to

    # get static findings and apply mitigations

    match_for_scan_type(from_app_guid=results_from_app_id, to_app_guid=results_to_app_id, dry_run=dry_run, scan_type='STATIC',
        from_sandbox_guid=results_from_sandbox_id,to_sandbox_guid=results_to_sandbox_id,propose_only=propose_only,id_list=id_list,fuzzy_match=fuzzy_match)

    match_for_scan_type(from_app_guid=results_from_app_id, to_app_guid=results_to_app_id, dry_run=dry_run, 
        scan_type='DYNAMIC',propose_only=propose_only,id_list=id_list)

if __name__ == '__main__':
    main()
