# Purpose:  API utilities
#
# Notes:    API credentials must be enabled on Veracode account and placed in ~/.veracode/credentials like
#
#           [default]
#           veracode_api_key_id = <YOUR_API_KEY_ID>
#           veracode_api_key_secret = <YOUR_API_KEY_SECRET>
#
#           and file permission set appropriately (chmod 600)

from urllib.parse import urlparse

import requests
import logging
from requests.adapters import HTTPAdapter

from .exceptions import VeracodeAPIError
from veracode_api_signing.exceptions import VeracodeAPISigningException
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


class VeracodeAPI:
    def __init__(self, proxies=None):
        self.baseurl = "https://analysiscenter.veracode.com/api"
        requests.Session().mount(self.baseurl, HTTPAdapter(max_retries=3))
        self.proxies = proxies

    def _request(self, url, method, params=None):
        if method not in ["GET", "POST"]:
            raise VeracodeAPIError("Unsupported HTTP method")

        try:
            session = requests.Session()
            session.mount(self.baseurl, HTTPAdapter(max_retries=3))
            request = requests.Request(method, url, params=params, auth=RequestsAuthPluginVeracodeHMAC())
            prepared_request = request.prepare()
            r = session.send(prepared_request, proxies=self.proxies)
            if 200 >= r.status_code <= 299:
                if r.content is None:
                    logging.debug("HTTP response body empty:\r\n{}\r\n{}\r\n{}\r\n\r\n{}\r\n{}\r\n{}\r\n"
                                  .format(r.request.url, r.request.headers, r.request.body, r.status_code, r.headers, r.content))
                    raise VeracodeAPIError("HTTP response body is empty")
                else:
                    return r.content
            else:
                logging.debug("HTTP error for request:\r\n{}\r\n{}\r\n{}\r\n\r\n{}\r\n{}\r\n{}\r\n"
                              .format(r.request.url, r.request.headers, r.request.body, r.status_code, r.headers, r.content))
                raise VeracodeAPIError("HTTP error: {}".format(r.status_code))
        except requests.exceptions.RequestException as e:
            logging.exception("Connection error")
            raise VeracodeAPIError(e)

    def get_app_list(self):
        """Returns all application profiles."""
        return self._request(self.baseurl + "/4.0/getapplist.do", "GET")

    def get_app_info(self, app_id):
        """Returns application profile info for a given app ID."""
        return self._request(self.baseurl + "/5.0/getappinfo.do", "GET", params={"app_id": app_id})

    def get_sandbox_list(self, app_id):
        """Returns a list of sandboxes for a given app ID"""
        return self._request(self.baseurl + "/5.0/getsandboxlist.do", "GET", params={"app_id": app_id})

    def get_build_list(self, app_id, sandbox_id=None):
        """Returns all builds for a given app ID."""
        if sandbox_id is None:
            params = {"app_id": app_id}
        else:
            params = {"app_id": app_id, "sandbox_id": sandbox_id}
        return self._request(self.baseurl + "/4.0/getbuildlist.do", "GET", params=params)
    
    def get_build_info(self, app_id, build_id, sandbox_id=None):
        """Returns build info for a given build ID."""
        if sandbox_id is None:
            params = {"app_id": app_id, "build_id": build_id}
        else:
            params = {"app_id": app_id, "build_id": build_id, "sandbox_id": sandbox_id}
        return self._request(self.baseurl + "/5.0/getbuildinfo.do", "GET", params=params)

    def get_detailed_report(self, build_id):
        """Returns a detailed report for a given build ID."""
        return self._request(self.baseurl + "/5.0/detailedreport.do", "GET", params={"build_id": build_id})

    def set_mitigation_info(self,build_id,flaw_id_list,action,comment, results_from_app_id):
        """Adds a new mitigation proposal, acceptance, rejection, or comment for a set of flaws for an application."""
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
        return self._request(self.baseurl + "/updatemitigationinfo.do", "POST", params=payload)
