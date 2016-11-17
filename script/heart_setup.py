#!/usr/bin/env python

import sys
import os
import shutil
import fileinput


def oidc_op_setup(distroot):
    for _dir in ['certs', 'keys', 'server_log', 'log']:
        os.mkdir(_dir)

    _dir = 'htdocs'
    _op_dir = os.path.join(distroot['oidc'], 'test_tool', 'test_op', 'oidc_op',
                           'heart_mako', _dir)
    shutil.copytree(_op_dir, _dir)

    _dir = 'static'
    _op_dir = os.path.join(distroot['oidc'], 'test_tool', 'test_op',
                           'oidc_op', _dir)
    shutil.copytree(_op_dir, _dir)

    _op_dir = os.path.join(distroot['oidc'], 'test_tool', 'test_op', 'oidc_op')
    for _fname in ['flows.yaml', 'run.sh', 'sslconf.py']:
        _file = os.path.join(_op_dir, _fname)
        shutil.copy(_file, '.')

    _file = os.path.join(_op_dir, 'config_examples', 'conf_TT.py')
    shutil.copy(_file, 'conf.py')

    for line in fileinput.input("conf.py", inplace=True):
        l = line.replace("../keys/", "./keys/").rstrip('\n')
        print(l)


def oidc_rp_setup(distroot):
    for _dir in ['certs', 'keys', 'server_log', 'log']:
        os.mkdir(_dir)

    _op_dir = os.path.join(distroot['oidc'], 'test_tool', 'test_rp', 'rpinst')
    for _dir in ['static', 'htdocs']:
        _src = os.path.join(_op_dir, _dir)
        shutil.copytree(_src, _dir)

    for _fname in ['flows.yaml', 'run.sh', 'example_conf.py', 'profiles.json',
                   'heart_interop_ports.csv']:
        _file = os.path.join(_op_dir, _fname)
        shutil.copy(_file, '.')


def oauth_as_setup(distroot):
    for _dir in ['certs', 'keys', 'server_log', 'log']:
        os.mkdir(_dir)

    _op_dir = os.path.join(distroot['oauth'], 'test_tool', 'test_as')
    for _dir in ['static', 'htdocs', 'flows']:
        _src = os.path.join(_op_dir, _dir)
        shutil.copytree(_src, _dir)

    for _fname in ['start.sh', 'example_conf.py', 'heart_interop_ports.csv']:
        _file = os.path.join(_op_dir, _fname)
        shutil.copy(_file, '.')


def oauth_rp_setup(distroot):
    for _dir in ['certs', 'keys', 'log']:
        os.mkdir(_dir)

    _op_dir = os.path.join(distroot['oauth'], 'test_tool', 'test_rp')
    for _dir in ['static', 'htdocs']:
        _src = os.path.join(_op_dir, _dir)
        shutil.copytree(_src, _dir)

    for _fname in ['flows.yaml', 'run.sh', 'example_conf.py', 'profiles.json']:
        _file = os.path.join(_op_dir, _fname)
        shutil.copy(_file, '.')


DIR = {
    'oidc_op': oidc_op_setup,
    'oidc_rp': oidc_rp_setup,
    'oauth2_as': oauth_as_setup,
    'oauth2_rp': oauth_rp_setup
}

if __name__ == '__main__':
    _distroot = {'oidc': sys.argv[1], 'oauth': sys.argv[2]}
    _root = sys.argv[3]
    os.makedirs(_root)

    os.chdir(_root)
    for _dir, func in DIR.items():
        os.mkdir(_dir)
        os.chdir(_dir)
        func(_distroot)
        os.chdir('..')
