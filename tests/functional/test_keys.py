import logging

import pytest

from pycryptoki.default_templates import \
    (CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
     CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224,
     CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256,

     CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP, CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,

     CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP,
     CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_2048_256,

     curve_list, get_default_key_template, get_default_key_pair_template,
     MECHANISM_LOOKUP_EXT)
from pycryptoki.defines import \
    (CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN, CKM_CAST3_KEY_GEN, CKM_CAST5_KEY_GEN,
     CKM_RC2_KEY_GEN, CKM_RC4_KEY_GEN, CKM_RC5_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN,
     CKM_AES_KEY_GEN, CKM_ARIA_KEY_GEN, CKM_SEED_KEY_GEN,

     CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN, CKM_DH_PKCS_KEY_PAIR_GEN,
     CKM_ECDSA_KEY_PAIR_GEN, CKA_ECDSA_PARAMS, CKM_KCDSA_KEY_PAIR_GEN, CKM_RSA_X9_31_KEY_PAIR_GEN,

     CKM_SHA1_KEY_DERIVATION, CKM_SHA224_KEY_DERIVATION, CKM_SHA256_KEY_DERIVATION,
     CKM_SHA384_KEY_DERIVATION, CKM_SHA512_KEY_DERIVATION, CKM_MD5_KEY_DERIVATION,
     CKM_MD2_KEY_DERIVATION,

     CKR_OK, CKA_VALUE_LEN, CKR_KEY_SIZE_RANGE)
from pycryptoki.key_generator import \
    c_generate_key, c_generate_key_pair, c_derive_key, c_generate_key_ex, c_destroy_object
from pycryptoki.mechanism import NullMech
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.test_functions import verify_object_attributes

logger = logging.getLogger(__name__)

KEYS = [CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN, CKM_CAST3_KEY_GEN, CKM_CAST5_KEY_GEN,
        CKM_GENERIC_SECRET_KEY_GEN, CKM_RC2_KEY_GEN, CKM_RC4_KEY_GEN, CKM_RC5_KEY_GEN,
        CKM_AES_KEY_GEN, CKM_SEED_KEY_GEN, CKM_ARIA_KEY_GEN]


def pair_params(key_gen):
    """ Return the params tuple given the key_gen mech """
    return (key_gen,) + get_default_key_pair_template(key_gen)


DSA_PUB_TEMPS = [CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224,
                 CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256]
KCDSA_P_TEMPS = [CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_2048_256]

KEY_PAIRS = [pair_params(CKM_RSA_PKCS_KEY_PAIR_GEN),
             pair_params(CKM_DH_PKCS_KEY_PAIR_GEN),
             pair_params(CKM_ECDSA_KEY_PAIR_GEN),
             pair_params(CKM_RSA_X9_31_KEY_PAIR_GEN)]
KEY_PAIRS.extend([(CKM_DSA_KEY_PAIR_GEN, x, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP) for x in DSA_PUB_TEMPS])
KEY_PAIRS.extend(
    [(CKM_KCDSA_KEY_PAIR_GEN, x, CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP) for x in KCDSA_P_TEMPS])

DERIVE_PARAMS = {CKM_SHA224_KEY_DERIVATION: "SHA224",
                 CKM_SHA256_KEY_DERIVATION: "SHA256",
                 CKM_SHA384_KEY_DERIVATION: "SHA384",
                 CKM_SHA512_KEY_DERIVATION: "SHA512"}
DERIVE_KEYS = {CKM_DES_KEY_GEN: "DES",
               CKM_DES2_KEY_GEN: "DES2",
               CKM_CAST3_KEY_GEN: "CAST3",
               CKM_GENERIC_SECRET_KEY_GEN: "GENERIC",
               CKM_CAST5_KEY_GEN: "CAST5",
               CKM_SEED_KEY_GEN: "SEED"}
DRV_TOO_LONG = {CKM_SHA1_KEY_DERIVATION: "SHA1",
                CKM_MD2_KEY_DERIVATION: "MD2",
                CKM_MD5_KEY_DERIVATION: "MD5"}
TOO_LONG_KEY = {CKM_DES3_KEY_GEN: "DES3",
                CKM_AES_KEY_GEN: "AES",
                CKM_ARIA_KEY_GEN: "ARIA"}
ALL_DERIVES = {k: v for d in [DERIVE_PARAMS, DRV_TOO_LONG] for k, v in d.items()}


class TestKeys(object):
    def verify_ret(self, ret, expected_ret):
        """ Verify ret check and len > 0"""
        assert ret == expected_ret, "Function should return: " + ret_vals_dictionary[expected_ret] \
                                    + ".\nInstead returned: " + ret_vals_dictionary[ret]

    def verify_key_len(self, k1, k2):
        """ Verify that key > 0"""
        assert k1 > 0, "Key should be > 0"
        assert k2 > 0, "Priv key should be > 0"

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session

    @pytest.mark.parametrize("key_type", KEYS, ids=[MECHANISM_LOOKUP_EXT[k][0] for k in KEYS])
    def test_generate_key(self, key_type):
        """
        Test generation of keys for sym. crypto systems
        :param key_type: key generation mechanism
        """
        key_template = get_default_key_template(key_type)
        ret, key_handle = c_generate_key(self.h_session, key_type, key_template)

        self.verify_ret(ret, CKR_OK)
        self.verify_key_len(key_handle, key_handle)

    @pytest.mark.parametrize(("key_type", "pub_key_temp", "prv_key_temp"), KEY_PAIRS,
                             ids=[MECHANISM_LOOKUP_EXT[k[0]][0] for k in KEY_PAIRS])
    def test_generate_key_pair(self, key_type, pub_key_temp, prv_key_temp):
        """
        Test generation of key pairs for asym. crypto systems
        :param key_type: key generation mechanism
        :param pub_key_temp: public key template
        :param prv_key_temp: private key template
        """
        ret, pub_key, prv_key = c_generate_key_pair(self.h_session, key_type,
                                                    pub_key_temp,
                                                    prv_key_temp)
        self.verify_ret(ret, CKR_OK)
        self.verify_key_len(pub_key, prv_key)

    @pytest.mark.parametrize("curve_type", list(curve_list.keys()))
    def test_generate_ecdsa_key_pairs(self, curve_type):
        """
        Test generate ECDSA key pairs
        :param curve_type:
        """
        CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP[CKA_ECDSA_PARAMS] = curve_list[curve_type]
        ret, public_key_handle, private_key_handle = c_generate_key_pair(self.h_session,
                                                                         CKM_ECDSA_KEY_PAIR_GEN,
                                                                         CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,
                                                                         CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP)
        try:
            self.verify_ret(ret, CKR_OK)
            self.verify_key_len(public_key_handle, private_key_handle)
        finally:
            if public_key_handle:
                c_destroy_object(self.h_session, public_key_handle)
            if private_key_handle:
                c_destroy_object(self.h_session, private_key_handle)

    @pytest.mark.parametrize("d_type", list(ALL_DERIVES.keys()), ids=list(ALL_DERIVES.values()))
    @pytest.mark.parametrize("key_type", list(DERIVE_KEYS.keys()), ids=list(DERIVE_KEYS.values()))
    def test_derive_key(self, key_type, d_type):
        """
        Test derive key for using parametrized hash
        :param key_type: Key-gen mechanism
        :param d_type: Hash mech
        """
        key_template = get_default_key_template(key_type)
        h_base_key = c_generate_key_ex(self.h_session, key_type, key_template)
        mech = NullMech(d_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session, h_base_key,
                                          key_template,
                                          mechanism=mech)
        try:
            self.verify_ret(ret, CKR_OK)
            verify_object_attributes(self.h_session, h_derived_key, key_template)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)

    @pytest.mark.parametrize("d_type", list(DRV_TOO_LONG.keys()), ids=list(DRV_TOO_LONG.values()))
    @pytest.mark.parametrize("key_type", list(TOO_LONG_KEY.keys()), ids=list(TOO_LONG_KEY.values()))
    def test_too_long_length_derives(self, key_type, d_type):
        """
        Verify that trying to derive a key that is too long for the given derivation function
        will return CKR_KEY_SIZE_RANGE
        :param key_type:
        :param d_type:
        """
        key_template = get_default_key_template(key_type)
        h_base_key = c_generate_key_ex(self.h_session, key_type, key_template)
        mech = NullMech(d_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session, h_base_key,
                                          key_template,
                                          mechanism=mech)
        try:
            self.verify_ret(ret, CKR_KEY_SIZE_RANGE)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)

    @pytest.mark.parametrize("d_type", list(DERIVE_PARAMS.keys()), ids=list(DERIVE_PARAMS.values()))
    @pytest.mark.parametrize("key_type", list(TOO_LONG_KEY.keys()), ids=list(TOO_LONG_KEY.values()))
    def test_long_length_derive_key(self, key_type, d_type):
        """
        Test deriving a key
        :param key_type: key generation mechanism
        :param d_type: derive mechanism
        """
        key_template = get_default_key_template(key_type)
        h_base_key = c_generate_key_ex(self.h_session, key_type, key_template)
        mech = NullMech(d_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session,
                                          h_base_key,
                                          key_template,
                                          mechanism=mech)
        try:
            self.verify_ret(ret, CKR_OK)
            verify_object_attributes(self.h_session, h_derived_key, key_template)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)
