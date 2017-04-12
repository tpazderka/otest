from otest.prof_util import from_profile
from otest.prof_util import map_prof
from otest.prof_util import repr_profile
from otest.prof_util import to_profile

TESTS = {
    'C.T.T.T': {'extra': False, 'enc': False, 'webfinger': True,
                'return_type': 'C', 'sig': False, 'none': False,
                'register': True, 'discover': True},
    'C.T.T.T..+': {'extra': True, 'enc': False, 'webfinger': True,
                   'return_type': 'C', 'sig': False, 'none': False,
                   'register': True, 'discover': True},
    'C.T.T.T.e.+': {'extra': True, 'enc': True, 'webfinger': True,
                    'return_type': 'C', 'sig': False, 'none': False,
                    'register': True, 'discover': True},
    'C.T.T.T.ens': {'extra': False, 'enc': True, 'webfinger': True,
                    'return_type': 'C', 'sig': True, 'none': True,
                    'register': True, 'discover': True},
    'C.T.T.T.es': {'extra': False, 'enc': True, 'webfinger': True,
                   'return_type': 'C', 'sig': True, 'none': False,
                   'register': True, 'discover': True},
    'C.T.T.T.s': {'extra': False, 'enc': False, 'webfinger': True,
                  'return_type': 'C', 'sig': True, 'none': False,
                  'register': True, 'discover': True},
    'CIT.F.F.F.s': {'extra': False, 'enc': False, 'webfinger': False,
                    'return_type': 'CIT', 'sig': True, 'none': False,
                    'register': False, 'discover': False},
    'I.F.T.F': {'extra': False, 'enc': False, 'webfinger': False,
                'return_type': 'I', 'sig': False, 'none': False,
                'register': False, 'discover': True},
    'I.T.T.T': {'extra': False, 'enc': False, 'webfinger': True,
                'return_type': 'I', 'sig': False, 'none': False,
                'register': True, 'discover': True}
}

TKEYS = list(TESTS.keys())
TKEYS.sort()


# print(TKEYS)


def test_from_to_code():
    for ex, val in TESTS.items():
        f = from_profile(ex)
        assert f == val
        t = to_profile(f)
        assert t == ex


def test_map_prof():
    assert map_prof(TKEYS[0], TKEYS[1]) is False
    assert map_prof(TKEYS[2], TKEYS[0])
    assert map_prof(TKEYS[0], TKEYS[2]) is False
    assert map_prof(TKEYS[3], TKEYS[4])
    assert map_prof(TKEYS[4], TKEYS[3]) is False
    assert map_prof(TKEYS[0], TKEYS[8]) is False
    assert map_prof(TKEYS[7], TKEYS[8]) is False
    assert map_prof(TKEYS[8], TKEYS[7]) is False
    assert map_prof(TKEYS[3], TKEYS[5])
    assert map_prof(TKEYS[4], TKEYS[5])


def test_repr_profile():
    rp = repr_profile(TKEYS[0].split('.'), representation="list")
    assert rp == ['code', 'webfinger', 'discovery', 'dynamic']

    rp = repr_profile(TKEYS[0].split('.'), representation="dict")
    assert rp == {'openid-configuration': 'discovery',
                  'registration': 'dynamic', 'return_type': 'code',
                  'webfinger': 'webfinger'}

    rp = repr_profile(TKEYS[3].split('.'), representation="list")
    assert rp == ['code', 'webfinger', 'discovery', 'dynamic',
                  'encrypt+none+sign']

    rp = repr_profile(TKEYS[6].split('.'), representation="list")
    assert rp == ['code+id_token+token', 'no-webfinger', 'no-discovery',
                  'static', 'sign']
