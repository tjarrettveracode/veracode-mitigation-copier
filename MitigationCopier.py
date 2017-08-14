import requests
import sys
import argparse
from lxml import etree
import logging


def results_api(build_id, api_user, api_password):
    payload = {'build_id': build_id}
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/detailedreport.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200 or '<error>' in r.content:
        logging.info('Error downloading results for Build ID ' + build_id)
        sys.exit('[*] Error downloading results for Build ID ' + build_id)
    logging.info('Downloaded results for Build ID ' + build_id)
    print '[*] Downloaded results for Build ID ' + build_id
    return r.content


def update_mitigation_info(build_id, flaw_id_list, action, comment, results_from_app_id, api_user, api_password):
    if action == 'Mitigate by Design':
        action = 'appdesign'
    elif action == 'Mitigate by Network Environment':
        action = 'netenv'
    elif action == 'Mitigate by OS Environment':
        action = 'osenv'
    elif action == 'Approve Mitigation':
        action = 'accepted'
    elif action == 'Reject Mitigation':
        action = 'rejected'
    elif action == 'Potential False Positive':
        action = 'fp'
    else:
        action = 'comment'
    payload = {'build_id': build_id, 'flaw_id_list': flaw_id_list, 'action': action, 'comment': comment}
    r = requests.post('https://analysiscenter.veracode.com/api/updatemitigationinfo.do', params=payload,
                      auth=(api_user, api_password))
    if r.status_code != 200 or '<error>' in r.content:
        logging.info('Error updating mitigation_info for ' + flaw_id_list + ' in Build ID ' + build_id)
        sys.exit('[*] Error updating mitigation_info for ' + flaw_id_list + ' in Build ID ' + build_id)
    logging.info(
        'Updated mitigation information to ' + action + ' for Flaw ID ' + flaw_id_list + ' in ' +
        results_from_app_id + ' in Build ID ' + build_id)


def main():
    parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM BUILD. For any flaws that have an '
                    'accepted mitigation, it checks the TO BUILD to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
    parser.add_argument('-f', '--frombuild', required=True, help='Build ID to copy from')
    parser.add_argument('-t', '--tobuild', required=True, help='Build ID to copy to')
    parser.add_argument('-u', '--username', required=True, help='Veracode API username')
    parser.add_argument('-p', '--password', required=True, help='Veracode API password')
    args = parser.parse_args()

    logging.basicConfig(filename='MitigationCopier.log',
                        format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=logging.INFO)

    # SET VARIABLES FOR FROM AND TO APPS
    results_from = results_api(args.frombuild, args.username, args.password)
    results_from_root = etree.fromstring(results_from)
    results_from_static_flaws = results_from_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
    results_from_flawid = [None] * len(results_from_static_flaws)
    results_from_unique = [None] * len(results_from_static_flaws)
    results_from_app_id = 'App ID ' + results_from_root.attrib['app_id'] + ' (' + results_from_root.attrib[
        'app_name'] + ')'

    results_to = results_api(args.tobuild, args.username, args.password)
    results_to_root = etree.fromstring(results_to)
    results_to_static_flaws = results_to_root.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
    results_to_flawid = [None] * len(results_to_static_flaws)
    results_to_unique = [None] * len(results_to_static_flaws)
    results_to_app_id = 'App ID ' + results_to_root.attrib['app_id'] + '(' + results_to_root.attrib['app_name'] + ')'

    # GET DATA FOR BUILD COPYING FROM
    iteration = -1
    for flaw in results_from_static_flaws:
        if flaw.attrib['mitigation_status'] == 'accepted':
            iteration += 1
            results_from_flawid[iteration] = flaw.attrib['issueid']
            results_from_unique[iteration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                             flaw.attrib['line']

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    iteration = -1
    for flaw in results_to_static_flaws:
        iteration += 1
        results_to_unique[iteration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                       flaw.attrib['line']
        results_to_flawid[iteration] = flaw.attrib['issueid']

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
            flaw_copy_to_list = results_to_root.findall(
                './/{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + str(to_id) + '"]')
            for flaw_copy_to in flaw_copy_to_list:
                # CHECK IF COPY TO IS ALREADY ACCEPTED
                if flaw_copy_to.attrib['mitigation_status'] != 'accepted':

                    mitigation_list = results_from_root.findall(
                        './/{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw[@issueid="' + str(
                            from_id) + '"]/{*}mitigations/{*}mitigation')

                    for mitigation_action in mitigation_list:
                        proposal_action = mitigation_action.attrib['action']
                        proposal_comment = '[COPIED FROM BUILD ' + args.frombuild + ' of App ID ' + \
                                           results_from_app_id + '] ' + mitigation_action.attrib['description']
                        update_mitigation_info(args.tobuild, to_id, proposal_action, proposal_comment,
                                               results_from_app_id, args.username,
                                               args.password)
                    counter += 1
                else:
                    logging.info('Flaw ID ' + str(to_id) + ' in ' + results_to_app_id + ' Build ID ' +
                                 args.tobuild + ' already has an accepted mitigation; skipped.')

    print '[*] Updated ' + str(counter) + ' flaws in ' + results_to_app_id + '. See log file for details.'


if __name__ == '__main__':
    main()
