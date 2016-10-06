import os

from future.backports.urllib.parse import quote_plus

from otest.log import with_or_without_slash
from otest.time_util import in_a_while

RESPONSE = 0
WEBFINGER = 1
DISCOVER = 2
REGISTER = 3
CRYPTO = 4
EXTRAS = 5

__author__ = 'roland'


class ProfileHandler(object):
    def __init__(self, session):
        self.session = session

    @staticmethod
    def webfinger(profile):
        return profile[WEBFINGER] == "T"

    @staticmethod
    def discover(profile):
        return profile[DISCOVER] == "T"

    @staticmethod
    def register(profile):
        return profile[REGISTER] == "T"

    def to_profile(self, representation="list"):
        return []

    def get_profile_info(self, test_id=None):
        try:
            _conv = self.session["conv"]
        except KeyError:
            pass
        else:
            try:
                iss = _conv.entity.provider_info["issuer"]
            except (TypeError, KeyError):
                iss = ""

            profile = self.to_profile("dict")

            if test_id is None:
                try:
                    test_id = self.session["testid"]
                except KeyError:
                    return {}

            return {"Issuer": iss, "Profile": profile,
                    "Test ID": test_id,
                    "Test description": self.session["node"].desc,
                    "Timestamp": in_a_while()}

        return {}

    def log_path(self, **kwargs):
        _conv = self.session["conv"]

        try:
            iss = _conv.entity.provider_info["issuer"]
        except (TypeError, KeyError):
            return ""
        else:
            qiss = quote_plus(iss)

        path = with_or_without_slash(os.path.join("log", qiss))
        if path is None:
            path = os.path.join("log", qiss)

        prof = ".".join(self.to_profile())

        if not os.path.isdir("{}/{}".format(path, prof)):
            os.makedirs("{}/{}".format(path, prof))

        if 'test_id' not in kwargs:
            _test_id = self.session["testid"]
        else:
            _test_id = kwargs['test_id']

        return "{}/{}/{}".format(path, prof, _test_id)


RT = {"C": "code", "I": "id_token", "T": "token", "CT": "code token",
      'CI': 'code id_token', 'IT': 'id_token token',
      'CIT': 'code id_token token'}


class SimpleProfileHandler(ProfileHandler):
    @staticmethod
    def webfinger(profile):
        return True

    @staticmethod
    def discover(profile):
        return True

    @staticmethod
    def register(profile):
        return True

    def get_profile_info(self, test_id=None):
        try:
            _conv = self.session["conv"]
        except KeyError:
            pass
        else:
            try:
                iss = _conv.entity.provider_info["issuer"]
            except AttributeError:
                iss = _conv.entity.baseurl
            except (TypeError, KeyError):
                iss = ""

            profile = RT[''.join(self.session["profile"])]

            if test_id is None:
                try:
                    test_id = self.session["testid"]
                except KeyError:
                    return {}

            return {"Issuer": iss, "Profile": profile,
                    "Test ID": test_id,
                    "Test description": self.session["node"].desc,
                    "Timestamp": in_a_while()}
        return {}

    def log_path(self, **kwargs):
        path = os.path.join("log", kwargs['sid'])

        prof = ".".join(self.to_profile())

        if not os.path.isdir("{}/{}".format(path, prof)):
            os.makedirs("{}/{}".format(path, prof))

        try:
            _test_id = kwargs['test_id']
        except KeyError:
            _test_id = self.session["testid"]

        return "{}/{}/{}".format(path, prof, _test_id)