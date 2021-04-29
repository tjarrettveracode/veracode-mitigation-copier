import requests
import sys
import argparse
import logging
import json
import datetime
from urllib import parse

import anticrlf
from veracode_api_py.api import VeracodeAPI as vapi
from veracode_api_py.constants import Constants

LINE_NUMBER_SLOP = 3 #adjust to allow for line number movement

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
    app_candidates = vapi().get_app_by_name(parse.quote(app_name_search))
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

def get_application_name(guid):
    app = vapi().get_app(guid)
    return app['profile']['name']

def get_findings_by_type(app_guid, scan_type='STATIC', sandbox_guid=None):
    findings = []
    if scan_type == 'STATIC':
        findings = vapi().get_findings(app_guid,scantype=scan_type,annot='TRUE',sandbox=sandbox_guid)
    elif scan_type == 'DYNAMIC':
        findings = vapi().get_findings(app_guid,scantype=scan_type,annot='TRUE')
        
    return findings

def logprint(log_msg):
    log.info(log_msg)
    print(log_msg)

def filter_approved(findings):
    return [f for f in findings if (f['finding_status']['resolution_status'] == 'APPROVED')]

def format_finding_lookup(flaw):
    finding_lookup = ''

    if flaw['scan_type'] == 'STATIC':
        finding_lookup = str(flaw['finding_details']['cwe']['id']) + flaw['scan_type'] + \
                                        flaw['finding_details']['file_name'] + \
                                        str(flaw['finding_details']['file_line_number'])
    elif flaw['scan_type'] == 'DYNAMIC':
        finding_lookup = str(flaw['finding_details']['cwe']['id']) + flaw['scan_type'] + \
                                        flaw['finding_details'].get('path','') + \
                                        flaw['finding_details'].get('vulnerable_parameter','')
        log.debug('Dynamic finding: {}'.format(finding_lookup))

    return finding_lookup

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
                'source_file': pf['finding_details'].get('file_path'),
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

def format_application_name(guid, app_name):
    formatted_name = 'application {} (guid: {})'.format(app_name,guid)
    return formatted_name

def get_matched_policy_finding(origin_finding, potential_findings, scan_type='STATIC'):
    match = None
    if scan_type == 'STATIC':
        if origin_finding['source_file'] is not None:
            match = next((pf for pf in potential_findings if ((origin_finding['cwe'] == int(pf['cwe'])) & 
                (origin_finding['source_file'].find(pf['source_file']) > -1 ) & 
                ((origin_finding['line'] - LINE_NUMBER_SLOP) <= pf['line'] <= (origin_finding['line'] + LINE_NUMBER_SLOP)))), None)
        else:
            # if we don't have source file info try matching on procedure and relative location
            match = next((pf for pf in potential_findings if ((origin_finding['cwe'] == int(pf['cwe'])) & 
                (origin_finding['procedure'].find(pf['procedure']) > -1 ) & 
                (origin_finding['relative_location'] == pf['relative_location'] ))), None)
    elif scan_type == 'DYNAMIC':
        match = next((pf for pf in potential_findings if ((origin_finding['cwe'] == int(pf['cwe'])) & 
            (origin_finding['path'] == pf['path']) &
            (origin_finding['vulnerable_parameter'] == pf['vulnerable_parameter']))), None)
    return match

def update_mitigation_info_rest(to_app_guid,flaw_id,action,comment,sandbox_guid=None):
    if action == 'CONFORMS' or action == 'DEVIATES':
        log.warning('Cannot copy {} mitigation for Flaw ID {} in {}'.format(action,flaw_id,to_app_guid))
        return
    elif action == 'APPROVED':
        action = Constants.ANNOT_TYPE[action]
    flaw_id_list = [flaw_id]
    if sandbox_guid==None:
        vapi().add_annotation(to_app_guid,flaw_id_list,comment,action)
    else:
        vapi().add_annotation(to_app_guid,flaw_id_list,comment,action,sandbox=sandbox_guid)
    log.info(
        'Updated mitigation information to {} for Flaw ID {} in {}'.format(action, str(flaw_id_list), to_app_guid))

def match_for_scan_type(from_app_guid, to_app_guid, dry_run, scan_type='STATIC',from_sandbox_guid=None, to_sandbox_guid=None):
    results_from_app_name = get_application_name(from_app_guid)
    formatted_from = format_application_name(from_app_guid,results_from_app_name)
    logprint('Getting {} findings for {}'.format(scan_type.lower(),formatted_from))
    findings_from = get_findings_by_type(from_app_guid,scan_type=scan_type, sandbox_guid=from_sandbox_guid)
    count_from = len(findings_from)
    logprint('Found {} {} findings in "from" {}'.format(count_from,scan_type.lower(),formatted_from))
    if count_from == 0:
        return 0 # no source findings to copy!   
   
    findings_from_approved = filter_approved(findings_from)

    if len(findings_from_approved) == 0:
        logprint('No approved findings in "from" {}. Exiting.'.format(formatted_from))
        return 0

    results_to_app_name = get_application_name(to_app_guid)
    formatted_to = format_application_name(to_app_guid,results_to_app_name)

    logprint('Getting {} findings for {}'.format(scan_type.lower(),formatted_to))
    findings_to = get_findings_by_type(to_app_guid,scan_type=scan_type, sandbox_guid=to_sandbox_guid)
    count_to = len(findings_to)
    logprint('Found {} {} findings in "to" {}'.format(count_to,scan_type.lower(),formatted_to))
    if count_to == 0:
        return 0 # no destination findings to mitigate!

    # GET DATA FOR BUILD COPYING FROM

    copy_array_from = create_match_format_policy( app_guid=from_app_guid, sandbox_guid=from_sandbox_guid, policy_findings=findings_from_approved,finding_type=scan_type)

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    copy_array_to = create_match_format_policy( app_guid=to_app_guid, sandbox_guid=to_sandbox_guid, policy_findings=findings_to,finding_type=scan_type)
    
    # We'll return how many mitigations we applied
    counter = 0

    # look for a match for each finding in the TO list and apply mitigations of the matching flaw, if found
    for thisfinding in copy_array_from:
        from_id = thisfinding['id']
        match = get_matched_policy_finding(thisfinding, copy_array_to, scan_type)

        if match == None:
            continue

        to_id = match.get('id')

        log.info('Source flaw {} in {} has a possible target match in flaw {} in {}.'.format(from_id,formatted_from,to_id,formatted_to))

        if match['finding']['finding_status']['resolution_status'] == 'APPROVED':
            logprint ('Flaw ID {} in {} already has an accepted mitigation; skipped.'.format(to_id,formatted_to))
            continue 

        mitigation_list = thisfinding['finding']['annotations']
        logprint ('Applying {} annotations for flaw ID {} in {}...'.format(len(mitigation_list),to_id,formatted_to))

        for mitigation_action in reversed(mitigation_list): #findings API puts most recent action first
            proposal_action = mitigation_action['action']
            proposal_comment = '[COPIED FROM APP {}] {}'.format(from_app_guid, mitigation_action['comment'])
            if not(dry_run):
                update_mitigation_info_rest(to_app_guid, to_id, proposal_action, proposal_comment, to_sandbox_guid)
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
    args = parser.parse_args()

    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # SET VARIABLES FOR FROM AND TO APPS
    results_from_app_id = args.fromapp
    results_to_app_id = args.toapp
    results_from_sandbox_id = args.fromsandbox
    results_to_sandbox_id = args.tosandbox
    prompt = args.prompt
    dry_run = args.dry_run

    if prompt:
        results_from_app_id = prompt_for_app("Enter the application name to copy mitigations from: ")
        results_to_app_id = prompt_for_app("Enter the application name to copy mitigations to: ")

    if ( results_from_app_id == None ) or ( results_to_app_id == None ):
        print('You must provide an application to copy mitigations to and from.')
        return

    # get static findings and apply mitigations

    match_for_scan_type(from_app_guid=results_from_app_id, to_app_guid=results_to_app_id, dry_run=dry_run, scan_type='STATIC',
        from_sandbox_guid=results_from_sandbox_id,to_sandbox_guid=results_to_sandbox_id)

    match_for_scan_type(from_app_guid=results_from_app_id, to_app_guid=results_to_app_id, dry_run=dry_run, scan_type='DYNAMIC')

if __name__ == '__main__':
    main()
