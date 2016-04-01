from oic.utils.keyio import create_and_store_rsa_key_pair

key = create_and_store_rsa_key_pair("keys/pyoidc_enc", size=2048)
key = create_and_store_rsa_key_pair("keys/pyoidc_sig", size=2048)
key = create_and_store_rsa_key_pair("keys/2nd_enc", size=2048)
key = create_and_store_rsa_key_pair("keys/2nd_sig", size=2048)
key = create_and_store_rsa_key_pair("keys/3rd_enc", size=2048)
key = create_and_store_rsa_key_pair("keys/3rd_sig", size=2048)