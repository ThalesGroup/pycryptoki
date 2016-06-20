"""
Test methods for pycryptoki 'hsm management' set of commands.
"""

import pytest

from . import config as hsm_config
from ...default_templates import CKM_RSA_PKCS_KEY_PAIR_GEN, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP
from ...defines import CKU_CRYPTO_USER, CKR_OK, \
    CKR_ATTRIBUTE_VALUE_INVALID, CKR_CANCEL, CKR_USER_NOT_AUTHORIZED, \
    CKA_CLASS, CKO_SECRET_KEY, CKA_KEY_TYPE, CKK_AES, CKA_TOKEN, \
    CKA_SENSITIVE, CKA_PRIVATE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, \
    CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE, CKA_VALUE_LEN, \
    CKA_EXTRACTABLE, CKA_LABEL, LUNA_TTYPE_CRYPTO, LUNA_TTYPE_RNG, \
    LUNA_DSS_SIGVERIFY_TEST
from ...hsm_management import ca_settokencertificatesignature, ca_hainit, ca_createloginchallenge, \
    ca_initializeremotepedvector, ca_deleteremotepedvector, ca_mtkrestore, \
    ca_mtkresplit, ca_mtkzeroize, c_performselftest
from ...key_generator import c_generate_key_pair
from ...return_values import ret_vals_dictionary


class TestAlgorithm(object):
    """Test algorithm class"""
    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config["test_slot"]

    @pytest.mark.parametrize("test_type",
                             [LUNA_TTYPE_CRYPTO,
                              LUNA_TTYPE_RNG,
                              LUNA_DSS_SIGVERIFY_TEST])
    def test_performselftest(self, test_type):
        """Tests performs self test

        :param test_type: test type

        """
        input_data = range(1000)
        input_length = 1000

        ret, data = c_performselftest(self.admin_slot,
                                      test_type,
                                      input_data,
                                      input_length)
        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]

    def test_settokencertsignature(self):
        """Tests set token certificate signature
        To do: fix attribute value
        """
        gen_temp = {CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_TOKEN: True,
                    CKA_SENSITIVE: True,
                    CKA_PRIVATE: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_SIGN: True,
                    CKA_VERIFY: True,
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_DERIVE: True,
                    CKA_VALUE_LEN: 16,
                    CKA_EXTRACTABLE: True,
                    CKA_LABEL: "AES Key"}

        access_level = 1
        customer_id = 1
        pub_template = gen_temp
        signature = range(4000)
        signature_length = 4000

        ret = ca_settokencertificatesignature(self.h_session,
                                              access_level,
                                              customer_id,
                                              pub_template,
                                              signature,
                                              signature_length)
        assert ret == CKR_ATTRIBUTE_VALUE_INVALID, \
            "Return code should be " + \
            ret_vals_dictionary[CKR_ATTRIBUTE_VALUE_INVALID] + \
            " not " + ret_vals_dictionary[ret]

    def test_hainit(self):
        """Tests performs HA init"""
        ret, pubkey_h, prikey_h = c_generate_key_pair(self.h_session,
                                                      CKM_RSA_PKCS_KEY_PAIR_GEN,
                                                      CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                                                      CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP)
        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]
        assert pubkey_h > 0, \
            "The public key handle returned should be non zero"
        assert prikey_h > 0, \
            "The private key handle returned should be non zero"

        ret = ca_hainit(self.h_session, prikey_h)

        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]

    @pytest.mark.xfail(reason="Not valid on PWD auth")
    def test_initializeremotepedvector(self):
        """Tests to initialize remote ped vector"""
        ret = ca_initializeremotepedvector(self.h_session)
        # since not SO return value must be CKR_USER_NOT_AUTHORIZED
        assert ret == CKR_USER_NOT_AUTHORIZED, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]

    @pytest.mark.xfail(reason="Not valid on PWD auth")
    def test_deleteremotepedvector(self):
        """Tests to delete remote ped vector"""
        ret = ca_deleteremotepedvector(self.h_session)
        # since not SO return value must be CKR_USER_NOT_AUTHORIZED
        assert ret == CKR_USER_NOT_AUTHORIZED, \
            "Return code should be " + ret_vals_dictionary[CKR_USER_NOT_AUTHORIZED] + \
            " not " + ret_vals_dictionary[ret]

    def test_mtkrestore(self):
        """Tests MTK restore"""
        ret = ca_mtkrestore(self.admin_slot)
        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]

    def test_mtkresplit(self):
        """Tests MTK resplit"""
        ret = ca_mtkresplit(self.admin_slot)
        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]

    def test_mtkzeroize(self):
        """Tests MTK zeroize"""
        ret = ca_mtkzeroize(self.admin_slot)
        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]
