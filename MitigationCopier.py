import requests
import sys
import argparse
from lxml import etree
import logging


def results_api(build_id, api_user, api_password):
    payload = {'build_id': build_id}
    r = requests.get('https://analysiscenter.veracode.com/api/5.0/detailedreport.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error downloading results for Build ID ' + build_id)
    print '[*] Downloaded results for Build ID ' + build_id
    return r.content


def update_mitigation_info(build_id, flaw_id_list, action, comment, api_user, api_password):
    payload = {'build_id': build_id, 'flaw_id_list': flaw_id_list, 'action': action, 'comment': comment}
    r = requests.post('https://analysiscenter.veracode.com/api/updatemitigationinfo.do', params=payload,
                      auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error updating mitigation_info')
    print '[*] Updated mitigation information to ' + action + ' for Flaw ID ' + flaw_id_list + ' in Build ID ' + build_id


def get_mitigation_info(build_id, flaw_id_list, api_user, api_password):
    payload = {'build_id': build_id, 'flaw_id_list': flaw_id_list}
    r = requests.get('https://analysiscenter.veracode.com/api/getmitigationinfo.do', params=payload,
                     auth=(api_user, api_password))
    if r.status_code != 200:
        sys.exit('[*] Error getting mitigation_info')
    print '[*] Received mitigation information for Flaw ID ' + flaw_id_list + ' in Build ID ' + build_id
    return r.content


def main():
    parser = argparse.ArgumentParser(
        description='This script looks at the results set of the FROM BUILD. For any flaws that have an '
                    'accepted mitigation, it checks the TO BUILD to see if that flaw exists. If it exists, '
                    'it copies all mitigation information.')
    parser.add_argument('-f', '--frombuild', required=True, help='Build ID to copy from')
    parser.add_argument('-t', '--tobuild', required=True, help='Build ID to copy to')
    parser.add_argument('-u', '--username', required=True, help='Veracode API username')
    parser.add_argument('-p', '--password', required=True, help='Veracode API password')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='Verbose (Debug) logging')
    args = parser.parse_args()

    # SET LOGGING
    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(filename='veracode_dynamic_scan_scheduler.log',
                        format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p',
                        level=log_level)

    # SET VARIABLES FOR FROM AND TO APPS
    results_from = results_api(args.frombuild, args.username, args.password)
    results_from = etree.fromstring(results_from)
    results_from = results_from.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
    results_from_flawid = [None] * len(results_from)
    results_from_unique = [None] * len(results_from)

    results_to = results_api(args.tobuild, args.username, args.password)
    results_to = etree.fromstring(results_to)
    results_to = results_to.findall('{*}severity/{*}category/{*}cwe/{*}staticflaws/{*}flaw')
    results_to_flawid = [None] * len(results_to)
    results_to_unique = [None] * len(results_to)

    # GET COUNT OF FLAWS
    counter = 0
    for flaw in results_from:
        if flaw.attrib['mitigation_status'] == 'accepted':
            counter +=1
    print '[*] Found  ' + str(counter) + ' flaws that match between builds and have approved mitigations.'

    # GET DATA FOR BUILD COPYING FROM
    iteration = -1
    for flaw in results_from:
        if flaw.attrib['mitigation_status'] == 'accepted':
            iteration += 1
            results_from_flawid[iteration] = flaw.attrib['issueid']
            results_from_unique[iteration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                             flaw.attrib['line']

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    iteration = -1
    for flaw in results_to:
        iteration += 1
        results_to_unique[iteration] = flaw.attrib['cweid'] + flaw.attrib['type'] + flaw.attrib['sourcefile'] + \
                                       flaw.attrib['line']
        results_to_flawid[iteration] = flaw.attrib['issueid']

    # FOR EACH UNIQUE VALUE IN RESULTS_TO_UNIQUE, CHECK IF IT'S IN RESULTS_FROM_UNIQUE, TAKE MITIGATION ACTION
    for i in range(0, len(results_to_unique) - 1):
        if results_to_unique[i] in results_from_unique:
            # FIND THE FLAW IDS FOR FROM AND TO
            from_id = results_from_flawid[results_from_unique.index(results_to_unique[i])]
            to_id = results_to_flawid[results_to_unique.index(results_to_unique[i])]

            # GET MITIGATION INFORMATION FOR FROM
            y = get_mitigation_info(args.frombuild, from_id, args.username, args.password)
            y = etree.fromstring(y)
            y = y.findall('{*}issue/{*}mitigation_action')

            for mitigation_action in y:
                proposal_action = mitigation_action.attrib['action']
                proposal_comment = '[COPIED FROM BUILD ' + args.frombuild + ']' + mitigation_action.attrib['comment']
                update_mitigation_info(args.tobuild, to_id, proposal_action, proposal_comment, args.username,
                                       args.password)
                logging.info('Updated mitigation info for Flaw ID ' + str(to_id) + ' in Build ID ' + args.tobuild +
                             ' based on Flaw ID ' + str(from_id) + ' in Build ID ' + str(args.frombuild))


if __name__ == '__main__':
    main()
