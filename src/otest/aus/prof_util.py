from otest import prof_util

__author__ = 'roland'

RT = {"C": "code", "T": "token", 'D': 'client_credentials'}


class ProfileHandler(prof_util.ProfileHandler):
    def to_profile(self, representation="list"):
        p = self.session.profile.split('.')
        prof = RT[p[0]]

        if representation == "list":
            return [prof]
        elif representation == "dict":
            return {'response_type': prof}
