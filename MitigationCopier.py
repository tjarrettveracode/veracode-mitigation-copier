import requests
import sys
import argparse
from lxml import etree
import logging
import json
import datetime

import anticrlf
from veracode_api_py import VeracodeAPI as vapi

def findings_api(app_guid):
    return vapi().get_findings(app_guid,scantype='ALL',annot='TRUE')

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def get_application_name(guid):
    app = vapi().get_app(guid)
    return app['profile']['name']

def get_latest_build(guid):
    # Assumes last build is the one to mitigate. Need to check build status
    app = vapi().get_app(guid)
    legacy_id = app['id']
    build_list = vapi().get_build_list(legacy_id)
    build_list_root = etree.fromstring(build_list)
    builds = []
    for build in build_list_root:
        builds.append(build.get('build_id'))

    #builds.sort() #we can actually have builds out of order if they are created in a different order than published

    return builds[len(builds)-1]

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
        logging.debug('Dynamic finding: {}'.format(finding_lookup))

    return finding_lookup

def format_application_name(guid, app_name):
    formatted_name = 'application {} (guid: {})'.format(app_name,guid)
    return formatted_name

def update_mitigation_info(build_id, flaw_id_list, action, comment, results_to_app_id):
    r = vapi().set_mitigation_info(build_id,flaw_id_list,action,comment)
    if '<error' in r.decode("UTF-8"):
        logging.info('Error updating mitigation_info for {} in Build ID {}: {}'.format(str(flaw_id_list),str(build_id),r.decode('UTF-8')))
        sys.exit('[*] Error updating mitigation_info for {} in Build ID {}'.format(str(flaw_id_list),str(build_id)) )
    logging.info(
        'Updated mitigation information to {} for Flaw ID {} in {} in Build ID {}'.format(action,\
            str(flaw_id_list), results_to_app_id, build_id))

def main():
    parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM APP. For any flaws that have an '
                    'accepted mitigation, it checks the TO APP to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
    parser.add_argument('-f', '--fromapp', help='App GUID to copy from',required=True)
    parser.add_argument('-t', '--toapp', help='App GUID to copy to',required=True)
    args = parser.parse_args()

    handler = logging.FileHandler(filename='MitigationCopier.log')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    logging.basicConfig(handlers={handler},
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=logging.INFO)

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # SET VARIABLES FOR FROM AND TO APPS
    results_from_app_id = args.fromapp
    results_from_app_name = get_application_name(results_from_app_id)
    formatted_from = format_application_name(results_from_app_id,results_from_app_name)
    print('Getting findings for {}'.format(formatted_from))
    findings_from = findings_api(args.fromapp)
    print('Found {} findings in "from" {}'.format(len(findings_from),formatted_from))
    results_from_flawid = [None] * len(findings_from)
    results_from_unique = [None] * len(findings_from)

    results_to_app_id = args.toapp
    results_to_app_name = get_application_name(args.toapp)
    formatted_to = format_application_name(results_to_app_id,results_to_app_name)
    print('Getting findings for {}'.format(formatted_to))
    findings_to = findings_api(args.toapp)
    print('Found {} findings in "to" {}'.format(len(findings_to),formatted_to))
    results_to_flawid = [None] * len(findings_to)
    results_to_unique = [None] * len(findings_to)
    results_to_build_id = get_latest_build(args.toapp)

     # GET DATA FOR BUILD COPYING FROM
    iteration = -1
    for flaw in findings_from:
        if flaw['finding_status']['resolution_status'] != 'APPROVED':
            continue

        finding_lookup = format_finding_lookup(flaw)
        if finding_lookup != '':
            iteration += 1
            results_from_flawid[iteration] = flaw['issue_id']
            results_from_unique[iteration] = finding_lookup

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    iteration = -1

    for flaw in findings_to:
        iteration += 1
        results_to_flawid[iteration] = flaw['issue_id']
        results_to_unique[iteration] = format_finding_lookup(flaw)
    
    # CREATE COUNTER VARIABLE
    counter = 0

   # CYCLE THROUGH RESULTS_TO_UNIQUE
    for i in range(0, len(results_to_unique) - 1):
        # CHECK IF IT'S IN RESULTS FROM
        if results_to_unique[i] in results_from_unique:
            # FIND THE FLAW IDS FOR FROM AND TO
            from_id = results_from_flawid[results_from_unique.index(results_to_unique[i])]
            to_id = results_to_flawid[results_to_unique.index(results_to_unique[i])]

            # CHECK IF IT'S ALREADY MITIGATED IN TO
            flaw_copy_to_list = next(flaw for flaw in findings_to if flaw['issue_id'] == to_id)
            # CHECK IF COPY TO IS ALREADY ACCEPTED
            if flaw_copy_to_list['finding_status']['resolution_status'] != 'APPROVED':

                source_flaw = next(flaw for flaw in findings_from if flaw['issue_id'] == from_id)
                mitigation_list = source_flaw['annotations']

                for mitigation_action in reversed(mitigation_list): #findings API puts most recent action first
                    proposal_action = mitigation_action['action']
                    proposal_comment = '[COPIED FROM APP {}}] {}'.format(args.fromapp, mitigation_action['comment'])
                    update_mitigation_info(results_to_build_id, to_id, proposal_action, proposal_comment, results_to_app_id)
                counter += 1
            else:
                logging.info('Flaw ID {} in {} already has an accepted mitigation; skipped.'.\
                    format(str(to_id),results_to_app_id))

    print('[*] Updated {} flaws in application {} (guid {}). See log file for details.'.\
                format(str(counter),results_to_app_name,results_to_app_id))

if __name__ == '__main__':
    main()
