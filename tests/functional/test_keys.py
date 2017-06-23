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

     CKR_OK, CKA_VALUE_LEN, CKR_KEY_SIZE_RANGE, CKD_NULL, CKM_ECDH1_DERIVE, CKA_CLASS,
     CKO_SECRET_KEY, CKA_EC_POINT, CKA_SENSITIVE, CKA_PRIVATE, CKA_DECRYPT, CKA_ENCRYPT, CKK_DES,
     CKA_KEY_TYPE, CKM_DES_ECB, CKR_MECHANISM_INVALID)
from pycryptoki.encryption import c_encrypt_ex, c_decrypt_ex
from pycryptoki.key_generator import \
    c_generate_key, c_generate_key_pair, c_derive_key, c_generate_key_ex, c_destroy_object, \
    c_derive_key_ex, c_generate_key_pair_ex
from pycryptoki.mechanism import NullMech
from pycryptoki.object_attr_lookup import c_get_attribute_value_ex
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.test_functions import verify_object_attributes
from .util import get_session_template

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

DATA = b"1234567812345678"


class TestKeys(object):
    """
    Tests Key & Key pair generation
    """

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
    def test_generate_key(self, key_type, valid_mechanisms):
        """
        Test generation of keys for sym. crypto systems
        :param key_type: key generation mechanism
        """
        key_template = get_session_template(get_default_key_template(key_type))
        ret, key_handle = c_generate_key(self.h_session, key_type, key_template)

        try:
            if key_type not in valid_mechanisms:
                self.verify_ret(ret, CKR_MECHANISM_INVALID)
            else:
                self.verify_ret(ret, CKR_OK)
                self.verify_key_len(key_handle, key_handle)
        finally:
            c_destroy_object(self.h_session, key_handle)

    @pytest.mark.parametrize(("key_type", "pub_key_temp", "prv_key_temp"), KEY_PAIRS,
                             ids=[MECHANISM_LOOKUP_EXT[k[0]][0] for k in KEY_PAIRS])
    def test_generate_key_pair(self, key_type, pub_key_temp, prv_key_temp, valid_mechanisms):
        """
        Test generation of key pairs for asym. crypto systems
        :param key_type: key generation mechanism
        :param pub_key_temp: public key template
        :param prv_key_temp: private key template
        """
        ret, pub_key, prv_key = c_generate_key_pair(self.h_session, key_type,
                                                    get_session_template(pub_key_temp),
                                                    get_session_template(prv_key_temp))
        try:
            if key_type not in valid_mechanisms:
                self.verify_ret(ret, CKR_MECHANISM_INVALID)
            else:
                self.verify_ret(ret, CKR_OK)
                self.verify_key_len(pub_key, prv_key)
        finally:
            c_destroy_object(self.h_session, prv_key)
            c_destroy_object(self.h_session, pub_key)

    @pytest.mark.parametrize("curve_type", list(curve_list.keys()))
    def test_generate_ecdsa_key_pairs(self, curve_type):
        """
        Test generate ECDSA key pairs
        :param curve_type:
        """
        pub_temp = CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP.copy()
        pub_temp[CKA_ECDSA_PARAMS] = curve_list[curve_type]
        data = c_generate_key_pair(self.h_session,
                                   CKM_ECDSA_KEY_PAIR_GEN,
                                   get_session_template(pub_temp),
                                   get_session_template(CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP))
        ret, public_key_handle, private_key_handle = data
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
    def test_derive_key(self, key_type, d_type, valid_mechanisms):
        """
        Test derive key for using parametrized hash
        :param key_type: Key-gen mechanism
        :param d_type: Hash mech
        """
        if key_type not in valid_mechanisms:
            pytest.skip("Not a valid mechanism on this product")
        key_template = get_session_template(get_default_key_template(key_type))
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
    def test_too_long_length_derives(self, key_type, d_type, valid_mechanisms):
        """
        Verify that trying to derive a key that is too long for the given derivation function
        will return CKR_KEY_SIZE_RANGE
        :param key_type:
        :param d_type:
        """
        if key_type not in valid_mechanisms:
            pytest.skip("Not a valid mechanism on this product")
        key_template = get_session_template(get_default_key_template(key_type))
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
    def test_long_length_derive_key(self, key_type, d_type, valid_mechanisms):
        """
        Test deriving a key
        :param key_type: key generation mechanism
        :param d_type: derive mechanism
        """
        key_template = get_session_template(get_default_key_template(key_type))
        if key_type not in valid_mechanisms:
            pytest.skip("Not a valid mechanism on this product")
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

    @pytest.mark.parametrize("curve_type", sorted(list(curve_list.keys())))
    def test_x9_key_derive(self, auth_session, curve_type):
        """
        Test we can do X9 key derivation
        """
        derived_key2 = derived_key1 = pub_key1 = pub_key2 = prv_key2 = prv_key1 = None
        derived_template = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_DES,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_PRIVATE: True,
            CKA_SENSITIVE: True
        }
        pub_temp, priv_temp = get_default_key_pair_template(CKM_ECDSA_KEY_PAIR_GEN)
        priv_temp = get_session_template(priv_temp)
        pub_temp = get_session_template(pub_temp)
        pub_temp[CKA_ECDSA_PARAMS] = curve_list[curve_type]

        pub_key1, prv_key1 = c_generate_key_pair_ex(auth_session,
                                                    CKM_ECDSA_KEY_PAIR_GEN,
                                                    pbkey_template=pub_temp,
                                                    prkey_template=priv_temp)
        try:
            pub_key2, prv_key2 = c_generate_key_pair_ex(auth_session,
                                                        CKM_ECDSA_KEY_PAIR_GEN,
                                                        pbkey_template=pub_temp,
                                                        prkey_template=priv_temp)

            pub_key1_raw = c_get_attribute_value_ex(auth_session,
                                                    pub_key1,
                                                    {CKA_EC_POINT: None})[CKA_EC_POINT]
            pub_key2_raw = c_get_attribute_value_ex(auth_session,
                                                    pub_key2,
                                                    {CKA_EC_POINT: None})[CKA_EC_POINT]
            derived_key1 = c_derive_key_ex(auth_session,
                                           h_base_key=prv_key2,
                                           template=derived_template,
                                           mechanism={"mech_type": CKM_ECDH1_DERIVE,
                                                      "params": {"kdf": CKD_NULL,
                                                                 "sharedData": None,
                                                                 "publicData": pub_key1_raw}})

            derived_key2 = c_derive_key_ex(auth_session,
                                           h_base_key=prv_key1,
                                           template=derived_template,
                                           mechanism={"mech_type": CKM_ECDH1_DERIVE,
                                                      "params": {"kdf": CKD_NULL,
                                                                 "sharedData": None,
                                                                 "publicData": pub_key2_raw}})
            cipher_data = c_encrypt_ex(auth_session,
                                       derived_key1,
                                       data=DATA,
                                       mechanism=CKM_DES_ECB)
            restored_text = c_decrypt_ex(auth_session,
                                         derived_key2,
                                         cipher_data,
                                         mechanism=CKM_DES_ECB)
            assert DATA == restored_text.rstrip(b'\x00')
        finally:
            for key in (pub_key1, prv_key1, pub_key2, prv_key2, derived_key1, derived_key2):
                if key:
                    c_destroy_object(auth_session, key)
