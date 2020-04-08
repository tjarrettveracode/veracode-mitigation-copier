# Purpose:  Data models


class Flaw(object):
    """A class that represents a flaw"""
    def __init__(self, id, date_first_occurrence, severity, cweid,
                 categoryname, affects_policy_compliance, remediationeffort,
                 remediation_status, mitigation_status_desc):
        super(Flaw, self).__init__()
        self.id = id
        self.date_first_occurrence = date_first_occurrence
        self.severity = severity
        self.cweid = cweid
        self.categoryname = categoryname
        self.affects_policy_compliance = affects_policy_compliance
        self.remediationeffort = remediationeffort
        self.remediation_status = remediation_status
        self.mitigation_status_desc = mitigation_status_desc

    @classmethod
    def to_headers(cls):
        return ["id", "date_first_occurrence", "severity", "cweid",
                "categoryname", "affects_policy_compliance", "remediationeffort",
                "remediation_status", "mitigation_status_desc"]

    def to_list(self):
        return [getattr(self, key) for key in Flaw.to_headers()]

    def __str__(self):
        return "{}, {}, {}, {}, {}, {}, {}, {}, {}".format(self.id, self.date_first_occurrence, self.severity, self.cweid,
                                                           self.categoryname, self.affects_policy_compliance, self.remediationeffort,
                                                           self.remediation_status, self.mitigation_status_desc)


class StaticFlaw(Flaw):
    """A class that represents a static analysis flaw"""
    def __init__(self, id, date_first_occurrence, severity, cweid,
                 categoryname, affects_policy_compliance, remediationeffort,
                 remediation_status, mitigation_status_desc,
                 exploitLevel, module, sourcefile, line):
        super(StaticFlaw, self).__init__(id, date_first_occurrence, severity, cweid,
                                         categoryname, affects_policy_compliance, remediationeffort,
                                         remediation_status, mitigation_status_desc)
        self.exploitLevel = exploitLevel
        self.module = module
        self.sourcefile = sourcefile
        self.line = line

    @classmethod
    def to_headers(cls):
        return super(StaticFlaw, cls).to_headers() + ["exploitLevel", "module", "sourcefile", "line"]

    def to_list(self):
        return [getattr(self, key) for key in StaticFlaw.to_headers()]

    def __str__(self):
        return super(StaticFlaw, self).__str__() + ", {}, {}, {}, {}".format(self.exploitLevel, self.module,
                                                                             self.sourcefile, self.line)


class DynamicFlaw(Flaw):
    """A class that represents a dynamic analysis flaw"""
    def __init__(self, id, date_first_occurrence, severity, cweid,
                 categoryname, affects_policy_compliance, remediationeffort,
                 remediation_status, mitigation_status_desc,
                 url):
        super(DynamicFlaw, self).__init__(id, date_first_occurrence, severity, cweid,
                                          categoryname, affects_policy_compliance, remediationeffort,
                                          remediation_status, mitigation_status_desc)
        self.url = url

    @classmethod
    def to_headers(cls):
        return super(DynamicFlaw, cls).to_headers() + ["url"]

    def to_list(self):
        return [getattr(self, key) for key in DynamicFlaw.to_headers()]

    def __str__(self):
        return super(DynamicFlaw, self).__str__() + ", {}".format(self.url)


class Build(object):
    """A class that represents a build"""
    def __init__(self, id, name, policy_updated_date, published_date=None, flaws=None):
        self.id = id
        self.name = name
        self.policy_updated_date = policy_updated_date
        self.published_date = published_date
        self.flaws = flaws
        self.type = None

    @classmethod
    def to_headers(cls):
        return ["id", "name", "type", "policy_updated_date", "published_date"]

    def to_list(self):
        return [getattr(self, key) for key in Build.to_headers()]

    def __str__(self):
        return "{}, {}, {}, {}, {}".format(self.id, self.name, self.type, self.policy_updated_date, self.published_date)


class StaticBuild(Build):
    """A class that represents a static analysis build"""
    def __init__(self, id, name, policy_updated_date, published_date=None, analysis_size_bytes=None, flaws=None):
        super(StaticBuild, self).__init__(id, name, policy_updated_date, published_date, flaws)
        self.type = "static"
        self.analysis_size_bytes = analysis_size_bytes

    @classmethod
    def to_headers(cls):
        return super(StaticBuild, cls).to_headers() + ["analysis_size_bytes"]

    def to_list(self):
        return [getattr(self, key) for key in StaticBuild.to_headers()]

    def __str__(self):
        return super(StaticBuild, self).__str__()


class DynamicBuild(Build):
    """A class that represents a dynamic analysis build"""
    def __init__(self, id, name, policy_updated_date, published_date=None, flaws=None):
        super(DynamicBuild, self).__init__(id, name, policy_updated_date, published_date, flaws)
        self.type = "dynamic"

    @classmethod
    def to_headers(cls):
        return super(DynamicBuild, cls).to_headers()

    def to_list(self):
        return [getattr(self, key) for key in DynamicBuild.to_headers()]

    def __str__(self):
        return super(DynamicBuild, self).__str__()


class Sandbox(object):
    """A class that represents a sandbox"""
    def __init__(self, id, name, builds=None):
        self.id = id
        self.name = name
        self.builds = builds

    @classmethod
    def to_headers(cls):
        return ["id", "name"]

    def to_list(self):
        return [getattr(self, key) for key in Sandbox.to_headers()]

    def __str__(self):
        return "{}, {}".format(self.id, self.name)


class App(object):
    """A class that represents an application"""
    def __init__(self, id, name, business_unit=None, sandboxes=None, builds=None):
        self.id = id
        self.name = name
        self.business_unit = business_unit
        self.sandboxes = sandboxes
        self.builds = builds

    @classmethod
    def to_headers(cls):
        return ["id", "name", "business_unit"]

    def to_list(self):
        return [getattr(self, key) for key in App.to_headers()]

    def __str__(self):
        return "{}, {}, {}".format(self.id, self.name, self.business_unit)
