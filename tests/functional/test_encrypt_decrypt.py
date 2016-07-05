""" Functional tests for encryption / decryption """
import logging
import pytest

from pycryptoki.default_templates import get_default_key_template, get_default_key_pair_template, \
    MECHANISM_LOOKUP_EXT
from pycryptoki.key_generator import c_generate_key_ex, c_generate_key_pair_ex, c_destroy_object
from pycryptoki.encryption import _split_string_into_list, _get_string_from_list, \
    c_encrypt, c_decrypt
from pycryptoki.return_values import ret_vals_dictionary

from pycryptoki.defines import (CKM_DES_CBC, CKM_DES_KEY_GEN,
                                CKM_AES_CBC, CKM_AES_ECB, CKM_AES_GCM, CKM_AES_KEY_GEN,
                                CKM_DES3_CBC, CKM_DES3_ECB, CKM_DES3_CBC_PAD, CKM_DES3_KEY_GEN,
                                CKM_CAST3_CBC, CKM_CAST3_ECB, CKM_CAST3_KEY_GEN,
                                CKM_CAST5_CBC, CKM_CAST5_ECB, CKM_CAST5_KEY_GEN,
                                CKM_RC4, CKM_RC4_KEY_GEN,
                                CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN,
                                CKM_RSA_X_509, CKM_RSA_X9_31_KEY_PAIR_GEN,)

from pycryptoki.defines import (CKR_OK, CKR_DATA_LEN_RANGE, CKR_DEVICE_MEMORY)

logger = logging.getLogger(__name__)

SYM_TABLE = {CKM_DES_CBC: CKM_DES_KEY_GEN,
             CKM_AES_CBC: CKM_AES_KEY_GEN,
             CKM_AES_ECB: CKM_AES_KEY_GEN,
             CKM_AES_GCM: CKM_AES_KEY_GEN,
             CKM_DES3_CBC: CKM_DES3_KEY_GEN,
             CKM_DES3_ECB: CKM_DES3_KEY_GEN,
             CKM_DES3_CBC_PAD: CKM_DES3_KEY_GEN,
             CKM_CAST3_CBC: CKM_CAST3_KEY_GEN,
             CKM_CAST3_ECB: CKM_CAST3_KEY_GEN,
             CKM_CAST5_CBC: CKM_CAST5_KEY_GEN,
             CKM_CAST5_ECB: CKM_CAST5_KEY_GEN,
             CKM_RC4: CKM_RC4_KEY_GEN}
ASYM_TABLE = {CKM_RSA_PKCS: CKM_RSA_PKCS_KEY_PAIR_GEN,
              CKM_RSA_X_509: CKM_RSA_X9_31_KEY_PAIR_GEN}

# MECH_FLAVOR: (<tuple of corresponding 'extra_params'>)
#   *** Update as additional test params are added ***
PARAM_TABLE = {CKM_DES_CBC: [{}, {'iv': list(range(8))}],
               CKM_AES_CBC: [{}, {'iv': list(range(16))}],
               CKM_AES_ECB: [{}],
               CKM_AES_GCM: [{'iv': list(range(16)), 'AAD': b'notsosecret', 'ulTagBits': 32}],
               CKM_DES3_CBC: [{}, {'iv': list(range(8))}],
               CKM_DES3_ECB: [{}],
               CKM_DES3_CBC_PAD: [{}, {'iv': list(range(8))}],
               CKM_CAST3_CBC: [{}, {'iv': list(range(8))}],
               CKM_CAST3_ECB: [{}],
               CKM_CAST5_CBC: [{}],
               CKM_CAST5_ECB: [{}],
               CKM_RC4: [{}],
               CKM_RSA_PKCS: [{}],
               CKM_RSA_X_509: [{}]}

# TESTING DATA
PAD = b"a" * 0xfff0
RAW = b"abcdefghijk"

# Flavors which auto-pad (will return 'CKR_OK' on un-padded(RAW) data)
PADDING_ALGORITHMS = [CKM_DES3_CBC_PAD, CKM_RC4, CKM_AES_GCM]

# Flavors which are not compatible with multi encrypt/decrypt
NOT_MULTI = [CKM_AES_GCM]


def ret_val(mech, data):
    """
    Determine expected ret during encryption of 'data' with 'mech'
    :param mech: mechanism
    :param data: type of data
    :return: expected return value
    """
    if data == RAW:
        if mech not in PADDING_ALGORITHMS:
            return CKR_DATA_LEN_RANGE
        else:
            return CKR_OK
    else:
        if mech == CKM_AES_GCM:
            return CKR_DEVICE_MEMORY
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
            ret_list.append((mech, params))

    return ret_list


def idfn(k_table):
    """ Generate test ids """
    id_list = []
    for s in scenarios(k_table):
        m_type, params = s
        id_str = MECHANISM_LOOKUP_EXT[m_type][0].replace("CKM_", "")
        for p in params:
            id_str += "-" + str(p)
        id_list.append(id_str)

    return id_list


@pytest.yield_fixture(scope='class')
def sym_keys(auth_session):
    """ Fixture containing all sym. keys"""
    keys = {}
    try:
        for key_type in SYM_TABLE.values():
            template = get_default_key_template(key_type)
            keys[key_type] = c_generate_key_ex(auth_session, key_type, template)
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
            keys[key_type] = c_generate_key_pair_ex(auth_session, key_type, pub_temp, prv_temp)
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
        assert ret == expected_ret, "Function should return: " + \
            ret_vals_dictionary[expected_ret] + ".\nInstead returned: " + ret_vals_dictionary[ret]

    def verify_data(self, starting_data, ending_data):
        """
        Assert that the data is the same before and after encryption / decryption
        :param starting_data: the initial data
        :param ending_data: the data after encryption / decryption
        """
        assert starting_data == ending_data, "The data after encryption/decryption is incorrect.\n" + \
            "Starting data: " + str(starting_data) + "\nEnding data: " + str(ending_data)

    @pytest.mark.parametrize('data', [PAD, RAW], ids=["Pad", "Raw"])
    @pytest.mark.parametrize(('m_type', 'params'), scenarios(SYM_TABLE), ids=idfn(SYM_TABLE))
    def test_sym_encrypt_decrypt(self, m_type, params, data, sym_keys, auth_session):
        """
        test encryption decryption calls of sym. crypto's
        :param m_type: mechanism flavor
        :param params: extra params
        :param data: testing data
        :param sym_keys: key fixture
        :param auth_session:
        """
        exp_ret = ret_val(m_type, data)
        h_key = sym_keys[SYM_TABLE[m_type]]

        ret, encrypted = c_encrypt(auth_session, m_type, h_key, data, extra_params=params)
        self.verify_ret(ret, exp_ret)

        # If not expecting error, proceed with testing
        if exp_ret == CKR_OK:
            ret, end_data = c_decrypt(auth_session, m_type, h_key, encrypted, extra_params=params)
            self.verify_ret(ret, exp_ret)

            self.verify_data(data, end_data)

    @pytest.mark.parametrize('data', [PAD, RAW], ids=["Pad", "Raw"])
    @pytest.mark.parametrize(('m_type', 'params'), scenarios(SYM_TABLE), ids=idfn(SYM_TABLE))
    def test_multi_sym_encrypt_decrypt(self, m_type, params, data, sym_keys, auth_session):
        """
        test encryption decryption calls of sym. crypto's
        :param m_type: mechanism flavor
        :param params: extra params
        :param data: testing data
        :param sym_keys: key fixture
        :param auth_session:
        """
        if m_type in NOT_MULTI:
            pytest.xfail("m_type does not support multi encrypt/decrypt")

        exp_ret = ret_val(m_type, data)
        h_key = sym_keys[SYM_TABLE[m_type]]
        encrypt_this = [data, data, data, data]

        ret, encrypted = c_encrypt(auth_session, m_type, h_key, encrypt_this, extra_params=params)
        self.verify_ret(ret, exp_ret)

        # If not expecting error, proceed with testing
        if exp_ret == CKR_OK:
            if m_type not in PADDING_ALGORITHMS:
                assert len(encrypted) == len(b"".join(encrypt_this))

            decrypt_this = _split_string_into_list(encrypted, len(data))
            ret, end_data = c_decrypt(auth_session, m_type, h_key, decrypt_this, extra_params=params)
            self.verify_ret(ret, exp_ret)

            self.verify_data(_get_string_from_list(encrypt_this), end_data)

    @pytest.mark.parametrize(('m_type', 'params'), scenarios(ASYM_TABLE), ids=idfn(ASYM_TABLE))
    def test_asym_encrypt_decrypt(self, m_type, params, asym_keys, auth_session):
        """
        test encryption decryption calls of asym. crypto's
        :param m_type: mechanism flavor
        :param params: extra params
        :param asym_keys: key fixture
        :param auth_session:
        """
        pub_key, prv_key = asym_keys[ASYM_TABLE[m_type]]

        ret, decrypt_this = c_encrypt(auth_session, m_type, pub_key, RAW, extra_params=params)
        self.verify_ret(ret, CKR_OK)

        ret, decrypted_data = c_decrypt(auth_session, m_type, prv_key, decrypt_this, extra_params=params)
        self.verify_ret(ret, CKR_OK)

        # Format to remove leading whitespace which causes problems during assert (RSA_X_509)
        decrypted_data = decrypted_data.replace("\x00", "")
        self.verify_data(RAW, decrypted_data)
