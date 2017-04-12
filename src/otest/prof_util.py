import os

from future.backports.urllib.parse import quote_plus

from otest.utils import with_or_without_slash
from otest.time_util import in_a_while

RESPONSE = 0
WEBFINGER = 1
DISCOVER = 2
REGISTER = 3
CRYPTO = 4
EXTRAS = 5

LABEL = ['return_type', 'webfinger', 'discover', 'register', 'crypto',
         'extra']

__author__ = 'roland'


EMAP = {'s': 'sig', 'n': 'none', 'e': 'enc'}
EKEYS = list(EMAP.keys())
EKEYS.sort()  # Make the result deterministic

RT = {"C": "code", "I": "id_token", "T": "token", "CT": "code token",
      'CI': 'code id_token', 'IT': 'id_token token',
      'CIT': 'code id_token token'}
RT_INV = dict([(v,k) for k,v in RT.items()])

WF = {'T': 'webfinger', 'F': 'no-webfinger'}
OC = {"T": "discovery", "F": "no-discovery"}
REG = {"T": "dynamic", "F": "static"}
CR = {"n": "none", "s": "sign", "e": "encrypt"}
EX = {"+": "extras"}
ATTR = ["return_type", "webfinger", "openid-configuration", "registration",
        "crypto", "extras"]


def simplify_return_type(spec):
    if ',' in spec:
        p = spec.split(',')
    elif ' ' in spec:
        p = spec.split(' ')
    else:
        p = [spec]
    p.sort()
    return RT_INV[' '.join(p)]


def abbr_return_type(spec):
    return RT[spec]


def verify_profile(profile):
    p = profile.split('.')
    if len(p) < 4:
        return False
    if p[0] not in ['C', 'I', 'IT', 'CT', 'CIT', 'CI']:
        return False
    for i in range(1, 4):
        if p[i] not in ['F', 'T']:
            return False
    return True


def from_profile(code):
    # Of the form <typ>.<webf>.<disc>.<reg>.*['+'/'n'/'s'/'se']
    # for example:
    # C.T.T.T..  - code response_type, webfinger & dynamic discovery &
    #                                   registration
    # CIT.F.T.F.. - response_type=["code","id_token","token"],
    #               No webfinger support,
    #               does dynamic discovery
    #               and static client registration

    p = code.split('.')

    _prof = {"return_type": p[RESPONSE],
             "webfinger": (p[WEBFINGER] == 'T'),
             "discover": (p[DISCOVER] == 'T'),
             "register": (p[REGISTER] == 'T'),
             "extra": False,
             "sig": False,
             'enc': False,
             'none': False}

    if len(p) > CRYPTO:
        for k, v in EMAP.items():
            if k in p[CRYPTO]:
                _prof[v] = True
    if len(p) > EXTRAS:
        if '+' in p[EXTRAS]:
            _prof['extra'] = True

    return _prof


def to_profile(pdict):
    code = pdict["return_type"]

    for key in ["webfinger", "discover", "register"]:
        try:
            if pdict[key]:
                code += ".T"
            else:
                code += ".F"
        except KeyError:
            code += ".F"

    ext = ''
    for k in EKEYS:
        try:
            if pdict[EMAP[k]]:
                ext += k
        except KeyError:
            pass

    try:
        _xtra = pdict['extra']
    except KeyError:
        _xtra = None

    if ext:
        code += '.' + ext
    elif _xtra:
        code += '.'

    if _xtra:
        code += '.+'

    return "".join(code)


def repr_profile(profile, representation="list", with_webfinger=True):
    """

    :param profile: Expected to be list of items
    :param representation: Which type of output that is expected
    :param with_webfinger: Is WebFinger specification included
    :return:
    """
    prof = ["+".join([RT[x] for x in profile[0]])]
    if with_webfinger:
        _spec = [WF, OC, REG]
    else:
        _spec = [OC, REG]

    i = 0
    for tag_text in _spec:
        i += 1
        try:
            prof.append("%s" % tag_text[profile[i]])
        except IndexError:
            pass

    try:
        i += 1
        prof.append("%s" % "+".join([CR[x] for x in profile[i]]))
    except (KeyError, IndexError):
        pass
    else:
        try:
            i += 1
            prof.append("%s" % EX[profile[i]])
        except (KeyError, IndexError):
            pass

    if representation == "list":
        return prof
    elif representation == "dict":
        ret = {}
        for r in range(0, len(prof)):
            ret[ATTR[r]] = prof[r]

        if "extras" in ret:
            ret["extras"] = True
        return ret


def do_registration(profile):
    return profile.split('.')[REGISTER]


def do_discovery(profile):
    return profile.split('.')[DISCOVER]


def return_type(profile):
    return profile.split('.')[RESPONSE]


def _cmp_prof(a, b):
    """

    :param a: list of strings
    :param b: list of strings
    :return: True/False if a maps to b
    """
    # basic, implicit, hybrid
    if b[RESPONSE] != "":
        if a[RESPONSE] not in b[RESPONSE].split(','):
            return False

    try:
        # dynamic discovery & registry
        for n in [WEBFINGER, DISCOVER, REGISTER]:
            if b[n] != "":
                if a[n] != b[n]:
                    return False
    except IndexError:
        print("Too short a:{}, b:{}".format(a, b))
        raise

    if len(a) > CRYPTO:
        if len(b) > CRYPTO:
            if b[CRYPTO] != '':
                if not set(a[CRYPTO]).issuperset(set(b[CRYPTO])):
                    return False

    if len(b) > EXTRAS:
        if len(a) > EXTRAS:
            if a[EXTRAS] != b[EXTRAS]:
                return False
        else:
            return False

    return True


def map_prof(a, b):
    """
    Checks that the demands in b are met by a

    :param a:
    :param b:
    :return: True/False
    """
    if a == b:
        return True

    if isinstance(b, list):
        return _cmp_prof(a, b)
    elif '.' in b:
        b = b.split('.')
        if '.' in a:
            a = a.split('.')
        return _cmp_prof(a, b)
    else:
        if b == '*':
            return True
        else:
            bl = b.split(',')
            if isinstance(a, list):
                if a[0] in bl:
                    return True
                else:
                    return False
            elif a in bl:
                return True
            else:
                return False


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

            return {
                "Issuer": iss, "Profile": profile,
                "Test ID": test_id,
                "Test description": self.session.test_flows[test_id]["desc"],
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

            return {
                "Issuer": iss, "Profile": profile,
                "Test ID": test_id,
                "Test description": self.session.test_flows[test_id]["desc"],
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
