import requests
import sys
import argparse
from lxml import etree
import logging
import json
import datetime

from helpers import api

def findings_api(app_guid):
    return api.VeracodeAPI().get_findings(app_guid)

def creds_expire_days_warning():
    creds = api.VeracodeAPI().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def get_application_name(guid):
    app = api.VeracodeAPI().get_app(guid)
    return app['profile']['name']

def get_latest_build(guid):
    # a little hacky. Assumes last build is the one to mitigate. Need to check build status
    app = api.VeracodeAPI().get_app(guid)
    legacy_id = app['id']
    build_list = api.VeracodeAPI().get_build_list(legacy_id)
    build_list_root = etree.fromstring(build_list)
    latest_build_id = build_list_root[len(build_list_root)-1].get('build_id')
    return latest_build_id

def format_application_name(guid, app_name):
    formatted_name = 'application ' + app_name + ' (guid: ' + guid + ')'
    return formatted_name

def update_mitigation_info(build_id, flaw_id_list, action, comment, results_from_app_id):

    r = api.VeracodeAPI().set_mitigation_info(build_id,flaw_id_list,action,comment)
    if '<error' in r.decode("UTF-8"):
        logging.info('Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
        sys.exit('[*] Error updating mitigation_info for ' + str(flaw_id_list) + ' in Build ID ' + str(build_id))
    logging.info(
        'Updated mitigation information to ' + action + ' for Flaw ID ' + str(flaw_id_list) + ' in ' +
        results_from_app_id + ' in Build ID ' + str(build_id))

def main():
    parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM APP. For any flaws that have an '
                    'accepted mitigation, it checks the TO APP to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
    parser.add_argument('-f', '--fromapp', help='App GUID to copy from',default='f72bd227-3f21-4521-9542-e52489eb7752')
    parser.add_argument('-t', '--toapp', help='App GUID to copy to',default='50da1ffe-4123-4436-9455-dfce04f6d302')
    args = parser.parse_args()

    logging.basicConfig(filename='MitigationCopier.log',
                        format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=logging.INFO)

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # SET VARIABLES FOR FROM AND TO APPS
    results_from_app_id = args.fromapp
    results_from_app_name = get_application_name(results_from_app_id)
    formatted_from = format_application_name(results_from_app_id,results_from_app_name)
    print('Getting findings for', formatted_from)
    findings_from = findings_api(args.fromapp)
    print('Found', len(findings_from) ,'findings in "from" ' + formatted_from)
    results_from_flawid = [None] * len(findings_from)
    results_from_unique = [None] * len(findings_from)

    results_to_app_id = args.toapp
    results_to_app_name = get_application_name(args.toapp)
    formatted_to = format_application_name(results_to_app_id,results_to_app_name)
    print('Getting findings for', formatted_to)
    findings_to = findings_api(args.toapp)
    print('Found', len(findings_to) ,'findings in "to" ' + formatted_to)
    results_to_flawid = [None] * len(findings_to)
    results_to_unique = [None] * len(findings_to)
    results_to_build_id = get_latest_build(args.toapp)

     # GET DATA FOR BUILD COPYING FROM
    iteration = -1
    for flaw in findings_from:
        if flaw['finding_status']['resolution_status'] == 'APPROVED':
            iteration += 1
            results_from_flawid[iteration] = flaw['issue_id']
            results_from_unique[iteration] = str(flaw['finding_details']['cwe']['id']) + flaw['scan_type'] + \
                                             flaw['finding_details']['file_name'] + \
                                             str(flaw['finding_details']['file_line_number'])

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    iteration = -1
    for flaw in findings_to:
        iteration += 1
        results_to_unique[iteration] = str(flaw['finding_details']['cwe']['id']) + flaw['scan_type'] + \
                                             flaw['finding_details']['file_name'] + \
                                             str(flaw['finding_details']['file_line_number'])
        results_to_flawid[iteration] = flaw['issue_id']
    
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
                    proposal_comment = '[COPIED FROM APP ' + args.fromapp + '] ' + mitigation_action['comment']
                    update_mitigation_info(results_to_build_id, to_id, proposal_action, proposal_comment, results_to_app_id)
                counter += 1
            else:
                logging.info('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' already has an accepted mitigation; skipped.')

    print('[*] Updated ' + str(counter) + ' flaws in application ' + results_to_app_name + ' (guid ' + results_to_app_id + \
         '). See log file for details.')

if __name__ == '__main__':
    main()
