""" Functional tests for encryption / decryption """
import collections
import logging
from distutils.version import LooseVersion

import pytest

from pycryptoki.default_templates import get_default_key_template, get_default_key_pair_template, \
    MECHANISM_LOOKUP_EXT
from pycryptoki.defines import (CKM_DES_CBC, CKM_DES_KEY_GEN,
                                CKM_AES_CBC, CKM_AES_ECB, CKM_AES_GCM, CKM_AES_KEY_GEN,
                                CKM_DES3_CBC, CKM_DES3_ECB, CKM_DES3_CBC_PAD, CKM_DES3_KEY_GEN,
                                CKM_CAST3_CBC, CKM_CAST3_ECB, CKM_CAST3_KEY_GEN,
                                CKM_CAST5_CBC, CKM_CAST5_ECB, CKM_CAST5_KEY_GEN,
                                CKM_RC2_CBC, CKM_RC2_ECB, CKM_RC2_CBC_PAD, CKM_RC2_KEY_GEN,
                                CKM_RC4, CKM_RC4_KEY_GEN,
                                CKM_SEED_CBC, CKM_SEED_CBC_PAD, CKM_SEED_ECB, CKM_SEED_KEY_GEN,
                                CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_RSA_PKCS_KEY_PAIR_GEN,
                                CKM_RSA_X_509, CKM_RSA_X9_31_KEY_PAIR_GEN,
                                CKM_SHA_1, CKG_MGF1_SHA1, CKM_AES_KWP, CKM_AES_KW,
                                CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID)
from pycryptoki.defines import (CKR_OK, CKR_DATA_LEN_RANGE, CKR_KEY_SIZE_RANGE)
from pycryptoki.encryption import c_encrypt, c_decrypt
from pycryptoki.key_generator import c_generate_key, c_generate_key_pair, c_destroy_object
from pycryptoki.return_values import ret_vals_dictionary
from . import config as hsm_config

logger = logging.getLogger(__name__)

SYM_TABLE = {CKM_DES_CBC: CKM_DES_KEY_GEN,
             CKM_AES_CBC: CKM_AES_KEY_GEN,
             CKM_AES_ECB: CKM_AES_KEY_GEN,
             CKM_AES_GCM: CKM_AES_KEY_GEN,
             CKM_AES_KW: CKM_AES_KEY_GEN,
             CKM_AES_KWP: CKM_AES_KEY_GEN,  # Note: Supported in Q3/Q4 2016 SA
             CKM_DES3_CBC: CKM_DES3_KEY_GEN,
             CKM_DES3_ECB: CKM_DES3_KEY_GEN,
             CKM_DES3_CBC_PAD: CKM_DES3_KEY_GEN,
             CKM_CAST3_CBC: CKM_CAST3_KEY_GEN,
             CKM_CAST3_ECB: CKM_CAST3_KEY_GEN,
             CKM_CAST5_CBC: CKM_CAST5_KEY_GEN,
             CKM_CAST5_ECB: CKM_CAST5_KEY_GEN,
             CKM_RC2_CBC: CKM_RC2_KEY_GEN,
             CKM_RC2_ECB: CKM_RC2_KEY_GEN,
             CKM_RC2_CBC_PAD: CKM_RC2_KEY_GEN,
             CKM_RC4: CKM_RC4_KEY_GEN,
             CKM_SEED_CBC: CKM_SEED_KEY_GEN,
             CKM_SEED_CBC_PAD: CKM_SEED_KEY_GEN,
             CKM_SEED_ECB: CKM_SEED_KEY_GEN}

ASYM_TABLE = {CKM_RSA_PKCS: CKM_RSA_PKCS_KEY_PAIR_GEN,
              CKM_RSA_PKCS_OAEP: CKM_RSA_PKCS_KEY_PAIR_GEN,
              CKM_RSA_X_509: CKM_RSA_X9_31_KEY_PAIR_GEN}

# MECH_FLAVOR: (<tuple of corresponding 'extra_params'>)
#   *** Update as additional test params are added ***
PARAM_TABLE = {CKM_DES_CBC: [{}, {'iv': list(range(8))}],
               CKM_AES_CBC: [{}, {'iv': list(range(16))}],
               CKM_AES_KW: [{'iv': []},
                            {'iv': list(range(8))}],
               CKM_AES_KWP: [{'iv': []},
                             {'iv': list(range(8))}],
               #  Note: Supported in Q3/Q4 2016 SA
               CKM_AES_ECB: [{}],
               CKM_AES_GCM: [{'iv': list(range(8)), 'AAD': b'notsosecret', 'ulTagBits': 32}],
               CKM_DES3_CBC: [{}, {'iv': list(range(8))}],
               CKM_DES3_ECB: [{}],
               CKM_DES3_CBC_PAD: [{}, {'iv': list(range(8))}],
               CKM_CAST3_CBC: [{}, {'iv': list(range(8))}],
               CKM_CAST3_ECB: [{}],
               CKM_CAST5_CBC: [{}],
               CKM_CAST5_ECB: [{}],
               CKM_RC2_CBC: [{'iv': list(range(8)), 'usEffectiveBits': 8}],
               CKM_RC2_ECB: [{'usEffectiveBits': 8}],
               CKM_RC2_CBC_PAD: [{'iv': list(range(8)), 'usEffectiveBits': 8}],
               CKM_RC4: [{}],
               CKM_SEED_CBC: [{}],
               CKM_SEED_CBC_PAD: [{}],
               CKM_SEED_ECB: [{}],
               CKM_RSA_PKCS: [{}],
               CKM_RSA_PKCS_OAEP: [{'hashAlg': CKM_SHA_1,
                                    'mgf': CKG_MGF1_SHA1,
                                    'sourceData': list(range(12))}],
               CKM_RSA_X_509: [{}]}

# TESTING DATA
PAD = b"a" * 0xfff0
RAW = b"abcdefghijk"

# Flavors which auto-pad (will return 'CKR_OK' on un-padded(RAW) data)
PADDING_ALGORITHMS = [CKM_DES3_CBC_PAD,
                      CKM_RC2_CBC_PAD,
                      CKM_RC4,
                      CKM_AES_GCM,
                      CKM_AES_KWP,
                      CKM_SEED_CBC_PAD]

# Ret error, however encrypt /decrypt is successful. Needs to be addressed at some point
KEY_SIZE_RANGE = [CKM_RC2_CBC, CKM_RC2_ECB, CKM_RC2_CBC_PAD]


def ret_val(mech, data, valid_mechs=None):
    """
    Determine expected ret during encryption of 'data' with 'mech'

    :param mech: mechanism
    :param data: type of data
    :param valid_mechs: List of valid mechanisms (retrieved by C_GetMechanismList())
    :return: expected return value
    """

    # Ret error, however encrypt /decrypt is successful. Needs to be addressed at some point
    if mech in KEY_SIZE_RANGE:
        return CKR_KEY_SIZE_RANGE

    if valid_mechs and mech not in valid_mechs:
        # If we are checking valid mechanisms and it's not in the list, ret will be incorrect.
        logger.warning("Mechanism %s (%s) wasn't found in valid mechanism list!",
                       mech, MECHANISM_LOOKUP_EXT.get(mech, ("Unknown",))[0])
        return CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID

    if data == RAW:
        if mech not in PADDING_ALGORITHMS and mech not in ASYM_TABLE:
            return CKR_DATA_LEN_RANGE
        else:
            return CKR_OK
    else:
        return CKR_OK


def scenarios(which_table):
    """
    :param which_table: SYM_KEY_TABLE or ASYM_KEY_TABLE
    :return: List of encrypt/decrypt test scenarios
    """
    ret_list = []
    for mech in which_table.keys():
        for params in PARAM_TABLE[mech]:
            if mech == CKM_AES_KW:
                ret_list.append(
                    pytest.mark.xfail(
                        LooseVersion(hsm_config.get('firmware', "6.2.1")) > LooseVersion("6.24.0"),
                        reason="Mechanism not list in C_GetMechanismList()")((mech, params)))
            else:
                ret_list.append((mech, params))

    return ret_list


def idfn(k_table):
    """ Generate test ids """
    id_list = []
    for test_args in scenarios(k_table):
        if not isinstance(test_args, tuple):
            # For mark decorators. The condition is arg #1 (can't be keyword, due to pytest bug)
            # Arg #2 is the tuple we want to unpack.
            test_args = test_args.args[1]
        m_type, params = test_args
        id_str = MECHANISM_LOOKUP_EXT.get(m_type, ("Unknown",))[0].replace("CKM_", "")
        for key, value in params.items():
            id_str += "-{}: {}".format(key, value)
        id_list.append(id_str)

    return id_list


@pytest.yield_fixture(scope='class')
def sym_keys(auth_session):
    """ Fixture containing all sym. keys"""
    keys = {}
    try:
        for key_type in SYM_TABLE.values():
            template = get_default_key_template(key_type)

            ret, key_handle = c_generate_key(auth_session, key_type, template)
            if ret == CKR_OK:
                keys[key_type] = key_handle
            else:
                logger.info("Failed to generate key: %s\nReturn code: %s", key_type, ret)
        yield keys

    finally:
        for handle in keys.values():
            c_destroy_object(auth_session, handle)


@pytest.yield_fixture(scope='class')
def asym_keys(auth_session):
    """ Fixture containing all asym. keys """
    keys = {}
    try:
        for key_type in ASYM_TABLE.values():
            pub_temp, prv_temp = get_default_key_pair_template(key_type)

            ret, pub_key, prv_key = c_generate_key_pair(auth_session, key_type, pub_temp, prv_temp)
            if ret == CKR_OK:
                keys[key_type] = (pub_key, prv_key)
            else:
                logger.info("Failed to generate key: %s\nReturn code: %s", key_type, ret)
        yield keys

    finally:
        for pub_key, prv_key in keys.values():
            c_destroy_object(auth_session, pub_key)
            c_destroy_object(auth_session, prv_key)


class TestEncryptData(object):
    def verify_ret(self, ret, expected_ret):
        """
        Assert that ret is as expected
        :param ret: the actual return value
        :param expected_ret: the expected return value
        """
        if isinstance(expected_ret, collections.Iterable):
            ret_codes = ", ".join(("{}".format(ret_vals_dictionary[val] for val in expected_ret)))
            err_message = ("Function should return one of: {}.\n"
                           "Instead returned: {}".format(ret_codes,
                                                         ret_vals_dictionary[ret]))
            assert ret in expected_ret, err_message
        else:
            err_message = ("Function should return: {}.\n"
                           "Instead returned: {}".format(ret_vals_dictionary[expected_ret],
                                                         ret_vals_dictionary[ret]))
            assert ret == expected_ret, err_message

    def verify_data(self, starting_data, ending_data):
        """
        Assert that the data is the same before and after encryption / decryption
        :param starting_data: the initial data
        :param ending_data: the data after encryption / decryption
        """
        assert starting_data == ending_data, ("The data after encryption/decryption is "
                                              "incorrect.\n Starting data: {}\n"
                                              "Ending data: {}".format(starting_data, ending_data))

    @pytest.mark.parametrize('data', [PAD, RAW], ids=["valid_data", "raw (pad-required)"])
    @pytest.mark.parametrize(('m_type', 'params'), scenarios(SYM_TABLE), ids=idfn(SYM_TABLE))
    def test_sym_encrypt_decrypt(self, m_type, params, data, sym_keys, auth_session,
                                 valid_mechanisms):
        """
        test encryption decryption calls of sym. crypto's
        :param m_type: mechanism flavor
        :param params: extra params
        :param data: testing data
        :param sym_keys: key fixture
        :param auth_session:
        """
        # Auto-fail when key-generation fails
        if sym_keys.get(SYM_TABLE[m_type]) is None:
            pytest.fail("No valid key found for {}".format(MECHANISM_LOOKUP_EXT[m_type][0]))

        exp_ret = ret_val(m_type, data, valid_mechanisms)
        h_key = sym_keys[SYM_TABLE[m_type]]

        # AES_GCM Requires smaller data sizes.
        if m_type == CKM_AES_GCM and data == PAD:
            data = "a" * 0xff0

        ret, encrypted = c_encrypt(auth_session, m_type, h_key, data, extra_params=params)
        self.verify_ret(ret, exp_ret)

        # If not expecting error, proceed with testing
        if exp_ret in (CKR_OK, KEY_SIZE_RANGE):
            ret, end_data = c_decrypt(auth_session, m_type, h_key, encrypted, extra_params=params)
            self.verify_ret(ret, exp_ret)

            self.verify_data(data, end_data)

    @pytest.mark.parametrize('data', [PAD, RAW], ids=["valid_data", "raw(pad-required)"])
    @pytest.mark.parametrize(('m_type', 'params'), scenarios(SYM_TABLE), ids=idfn(SYM_TABLE))
    def test_multi_sym_encrypt_decrypt(self, m_type, params, data, sym_keys, auth_session,
                                       valid_mechanisms):
        """
        test encryption decryption calls of sym. crypto's

        :param m_type: mechanism flavor
        :param params: extra params
        :param data: testing data
        :param sym_keys: key fixture
        :param auth_session:
        """

        # Auto-fail when key-generation is fails
        if sym_keys.get(SYM_TABLE[m_type]) is None:
            pytest.fail("No valid key found for {}".format(MECHANISM_LOOKUP_EXT[m_type][0]))

        # AES_KW will fail on very large data sizes
        # AES_GCM requires smaller data sizes as well.
        if m_type in (CKM_AES_KW, CKM_AES_GCM) and data == PAD:
            data = "a" * 256

        exp_ret = ret_val(m_type, data, valid_mechanisms)
        h_key = sym_keys[SYM_TABLE[m_type]]
        encrypt_this = [data, data, data, data]

        ret, encrypted = c_encrypt(auth_session, m_type, h_key, encrypt_this, extra_params=params)
        self.verify_ret(ret, exp_ret)

        # If not expecting error, proceed with testing
        if exp_ret in (CKR_OK, KEY_SIZE_RANGE):
            if m_type not in PADDING_ALGORITHMS and m_type != CKM_AES_KW:
                assert len(encrypted) == len(b"".join(encrypt_this))

            ret, end_data = c_decrypt(auth_session, m_type, h_key, encrypted,
                                      extra_params=params)
            self.verify_ret(ret, exp_ret)
            if m_type in PADDING_ALGORITHMS:
                end_data = end_data.rstrip(b"\x00")
            self.verify_data(b"".join(encrypt_this), end_data)

    @pytest.mark.parametrize(('m_type', 'params'), scenarios(ASYM_TABLE), ids=idfn(ASYM_TABLE))
    def test_asym_encrypt_decrypt(self, m_type, params, asym_keys, auth_session, valid_mechanisms):
        """
        test encryption decryption calls of asym. crypto's
        :param m_type: mechanism flavor
        :param params: extra params
        :param asym_keys: key fixture
        :param auth_session:
        """
        if asym_keys.get(ASYM_TABLE[m_type]) is None:
            pytest.fail("No valid key found for {}".format(MECHANISM_LOOKUP_EXT[m_type][0]))

        expected_retcode = ret_val(m_type, RAW, valid_mechanisms)
        pub_key, prv_key = asym_keys[ASYM_TABLE[m_type]]

        ret, decrypt_this = c_encrypt(auth_session, m_type, pub_key, RAW, extra_params=params)
        self.verify_ret(ret, expected_retcode)

        if expected_retcode == CKR_OK:
            ret, decrypted_data = c_decrypt(auth_session, m_type, prv_key, decrypt_this,
                                            extra_params=params)
            self.verify_ret(ret, expected_retcode)

        self.verify_data(RAW, decrypted_data.replace(b"\x00", b""))
