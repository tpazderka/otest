import json
import os
import re

PAT = re.compile('\${([A-Z_0-9]*)}')

ABBR = {
    "code": 'C',
    "id_token": 'I',
    "id_token token": 'IT',
    "code id_token": 'CI',
    "code token": 'CT',
    "code id_token token": 'CIT',
    "dynamic": 'DYN',
    "configuration": 'CNF'
}

EXP = dict([(v, k) for k, v in ABBR.items()])

GRPS = [
    "Discovery", "Dynamic Client Registration",
    "Response Type and Response Mode", "claims Request Parameter",
    "request_uri Request Parameter", "scope Request Parameter",
    "nonce Request Parameter", "Client Authentication",
    "ID Token", "Key Rotation", "Claims Types", "UserInfo Endpoint"
]


def replace_with_url(txt, links):
    for m in PAT.findall(txt):
        try:
            _url = links['URL'][m]
        except KeyError:
            pass
        else:
            txt = txt.replace('${%s}' % m, _url)

    return txt


def replace_with_link(txt, links):
    for m in PAT.findall(txt):
        try:
            _url, tag = links['LINK'][m]
        except KeyError:
            pass
        else:
            _li = replace_with_url(_url, links)
            _href = '<a href="{}">{}</a>'.format(_li, tag)
            txt = txt.replace('${%s}' % m, _href)
    return txt


class Flow(object):
    def __init__(self, fdir):
        self.fdir = fdir

    def __getitem__(self, tid):
        """
        Get the flow description given a test ID

        :param tid: The test ID
        :return: A dictionary representation of the description
        """
        fname = os.path.join(self.fdir, tid)
        fp = open(fname, 'r')
        try:
            _info = json.load(fp)
        except Exception:
            raise KeyError(tid)
        finally:
            fp.close()

        return _info

    def items(self):
        """
        Return all flow descriptions.
        It is assumed that all files with names that has the postfix '.json'
        prepresents flow descriptions.

        :return:
        """
        for fn in os.listdir(self.fdir):
            if fn.endswith('.json'):
                fn = fn[:-4]
                yield((fn, self[fn]))

    def keys(self):
        """
        Return all Test IDs
        :return: list of test IDs
        """
        for fn in os.listdir(self.fdir):
            if fn.endswith('.json'):
                yield(fn[:-4])
