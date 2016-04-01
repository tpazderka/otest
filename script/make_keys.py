#!/usr/bin/env python
from oic.utils.keyio import create_and_store_rsa_key_pair

for name in ['pyoidc', '2nd', '3rd']:
    create_and_store_rsa_key_pair("keys/{}_enc".format(name), size=2048)
    create_and_store_rsa_key_pair("keys/{}_sig".format(name), size=2048)
