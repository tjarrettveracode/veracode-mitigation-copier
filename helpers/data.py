# Purpose:  Convert Veracode XML elements to Python objects.
from __future__ import print_function

import sys
import xml.etree.ElementTree as ETree
try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO
import pytz
from dateutil import parser

from veracodetocsv.helpers import models
from veracodetocsv.helpers.exceptions import VeracodeError, VeracodeAPIError


def parse_and_remove_xml_namespaces(xml_string):
    if sys.version_info >= (3,):
        it = ETree.iterparse(BytesIO(xml_string))
    else:
        it = ETree.iterparse(StringIO(xml_string))
    for _, el in it:
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]  # strip all namespaces
    return it.root


class DataLoader:
    def __init__(self, api, build_tools):
        self.api = api
        self.build_tools = build_tools

    def _get_apps(self):
        """Returns a list of apps"""
        try:
            app_list_xml = self.api.get_app_list()
        except VeracodeAPIError as e:
            raise VeracodeError(e)

        app_list_root_element = parse_and_remove_xml_namespaces(app_list_xml)
        app_elements = app_list_root_element.findall("app")

        apps = []
        for app_element in app_elements:
            apps.append(models.App(app_element.attrib["app_id"], app_element.attrib["app_name"]))

        return apps

    def _get_app_info(self, app_id):
        """Returns a dict holding app info"""
        try:
            app_info_xml = self.api.get_app_info(app_id)
        except VeracodeAPIError as e:
            raise VeracodeError(e)

        app_info_root_element = parse_and_remove_xml_namespaces(app_info_xml)

        return app_info_root_element.find("application").attrib

    def _get_sandboxes(self, app_id):
        """Returns a list of sandboxes"""
        try:
            sandbox_list_xml = self.api.get_sandbox_list(app_id)
        except VeracodeAPIError as e:
            raise VeracodeError(e)

        sandbox_list_root_element = parse_and_remove_xml_namespaces(sandbox_list_xml)
        sandbox_elements = sandbox_list_root_element.findall("sandbox")
        sandboxes = []

        for sandbox_element in sandbox_elements:
            sandboxes.append(models.Sandbox(sandbox_element.attrib["sandbox_id"], sandbox_element.attrib["sandbox_name"]))

        return sandboxes

    def _get_builds(self, app_id, include_static_builds, include_dynamic_builds, sandbox_id=None):
        """Returns a list of builds"""
        try:
            if sandbox_id is None:
                build_list_xml = self.api.get_build_list(app_id)
            else:
                build_list_xml = self.api.get_build_list(app_id, sandbox_id)
        except VeracodeAPIError as e:
            raise VeracodeError(e)

        build_list_root_element = parse_and_remove_xml_namespaces(build_list_xml)
        build_elements = build_list_root_element.findall("build")

        builds = []
        for build_element in build_elements:
            if sandbox_id is None:
                if "policy_updated_date" in build_element.attrib:
                    policy_updated_date_string = build_element.attrib["policy_updated_date"][:22] + \
                                                 build_element.attrib["policy_updated_date"][23:]
                    policy_updated_date = parser.parse(policy_updated_date_string).astimezone(pytz.utc)
                else:
                    # In this case it's a build that hasn't completed yet, as it's not a sandbox and should have a
                    # policy updated date if the build has been published.
                    continue
            else:
                policy_updated_date = None

            if include_static_builds and "dynamic_scan_type" not in build_element.attrib:
                builds.append(models.StaticBuild(build_element.attrib["build_id"], build_element.attrib["version"], policy_updated_date))
            if include_dynamic_builds and "dynamic_scan_type" in build_element.attrib:
                builds.append(models.DynamicBuild(build_element.attrib["build_id"], build_element.attrib["version"], policy_updated_date))

        return builds

    def _get_build_info(self, app_id, build_id, sandbox_id=None):
        """Returns an XML element holding build info"""
        try:
            build_info_xml = self.api.get_build_info(app_id, build_id, sandbox_id)
        except VeracodeAPIError as e:
            raise VeracodeError(e)

        build_info_root_element = parse_and_remove_xml_namespaces(build_info_xml)

        return build_info_root_element.find("build")
        
    def _get_flaws(self, build_id, build_type):
        """Returns a list of flaws"""
        try:
            detailed_report_xml = self.api.get_detailed_report(build_id)
        except VeracodeAPIError as e:
            raise VeracodeError(e)

        detailed_report_root_element = parse_and_remove_xml_namespaces(detailed_report_xml)

        # Use xpath to find all flaws in the detailed report
        findall_string = "severity/category/cwe/" + build_type + "flaws/flaw"
        flaw_elements = detailed_report_root_element.findall(findall_string)
        flaw_elements.sort(key=lambda flaw: int(flaw.attrib["issueid"]))

        flaws = []
        for flaw_element in flaw_elements:
            date_first_occurrence = parser.parse(flaw_element.attrib["date_first_occurrence"]).astimezone(pytz.utc)
            if build_type == "static":
                flaws.append(models.StaticFlaw(flaw_element.attrib["issueid"], date_first_occurrence,
                                               flaw_element.attrib["severity"], flaw_element.attrib["cweid"],
                                               flaw_element.attrib["categoryname"], flaw_element.attrib["affects_policy_compliance"],
                                               flaw_element.attrib["remediationeffort"], flaw_element.attrib["remediation_status"],
                                               flaw_element.attrib["mitigation_status_desc"], flaw_element.attrib["exploitLevel"],
                                               flaw_element.attrib["module"], flaw_element.attrib["sourcefile"], flaw_element.attrib["line"]))
            elif build_type == "dynamic":
                flaws.append(models.DynamicFlaw(flaw_element.attrib["issueid"], date_first_occurrence,
                                                flaw_element.attrib["severity"], flaw_element.attrib["cweid"],
                                                flaw_element.attrib["categoryname"], flaw_element.attrib["affects_policy_compliance"],
                                                flaw_element.attrib["remediationeffort"], flaw_element.attrib["remediation_status"],
                                                flaw_element.attrib["mitigation_status_desc"], flaw_element.attrib["url"]))

        if build_type == "static":
            static_analysis_element = detailed_report_root_element.find("static-analysis")
            analysis_size_bytes = None
            if static_analysis_element is not None:
                analysis_size_bytes = static_analysis_element.attrib["analysis_size_bytes"]
            return flaws, analysis_size_bytes
        else:
            return flaws

    def get_data(self, include_static_builds=True, include_dynamic_builds=True, app_include_list=None, include_sandboxes=False):
        """Returns a list of populated apps"""
        apps = self._get_apps()
        if app_include_list:
            apps = [app for app in apps if app.name in app_include_list]

        print("{} applications found in Veracode account".format(len(apps)))

        for app in apps:
            app_info = self._get_app_info(app.id)
            app.business_unit = app_info["business_unit"]
            builds = self._get_builds(app.id, include_static_builds, include_dynamic_builds)
            app.builds = [build for build in builds if self.build_tools.build_should_be_processed(app.id, build.id, build.policy_updated_date)]

            print(u"{}: {} policy builds".format(app.name, len(app.builds)))

            for build in app.builds:
                analysis_unit_attrib = self._get_build_info(app.id, build.id).find("analysis_unit").attrib
                if "published_date" in analysis_unit_attrib:
                    published_date_string = analysis_unit_attrib["published_date"][:22] + analysis_unit_attrib["published_date"][23:]
                    build.published_date = parser.parse(published_date_string).astimezone(pytz.utc)
                if build.type == "static":
                    build.flaws, build.analysis_size_bytes = self._get_flaws(build.id, build.type)
                else:
                    build.flaws = self._get_flaws(build.id, build.type)

            if include_sandboxes:
                app.sandboxes = self._get_sandboxes(app.id)

                print(u"{}: {} sandboxes".format(app.name, len(app.sandboxes)))

                for sandbox in app.sandboxes:
                    builds = self._get_builds(app.id, include_static_builds, include_dynamic_builds, sandbox.id)
                    sandbox.builds = [build for build in builds if self.build_tools.build_should_be_processed(app.id, build.id, build.policy_updated_date)]
                    for build in sandbox.builds:
                        analysis_unit_attrib = self._get_build_info(app.id, build.id, sandbox.id).find("analysis_unit").attrib
                        if "published_date" in analysis_unit_attrib:
                            published_date_string = analysis_unit_attrib["published_date"][:22] + analysis_unit_attrib["published_date"][23:]
                            build.published_date = parser.parse(published_date_string).astimezone(pytz.utc)
                        build.flaws, build.analysis_size_bytes = self._get_flaws(build.id, build.type)

        return apps

    def get_headers(self, build_type, include_sandbox=False):
        """Returns headers for a csv file"""
        app_headers = ["app_" + header for header in models.App.to_headers()]
        build_headers = ["build_" + header for header in (models.StaticBuild.to_headers() if build_type == "static" else models.DynamicBuild.to_headers())]
        flaw_headers = ["flaw_" + header for header in(models.StaticFlaw.to_headers() if build_type == "static" else models.DynamicFlaw.to_headers())]
        headers = app_headers + build_headers + flaw_headers
        if include_sandbox:
            headers += ["sandbox_" + header for header in models.Sandbox.to_headers()]

        return headers
