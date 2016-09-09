from otest import prof_util

__author__ = 'roland'

RESPONSE = 0
WEBFINGER = 1
DISCOVER = 2
REGISTER = 3
CRYPTO = 4
EXTRAS = 5

RT = {"C": "code", "T": "token", 'D': 'client_credentials'}


class ProfileHandler(prof_util.ProfileHandler):
    def to_profile(self, representation="list"):
        prof = RT[self.session["profile"]]

        if representation == "list":
            return [prof]
        elif representation == "dict":
            return {'response_type': prof}
