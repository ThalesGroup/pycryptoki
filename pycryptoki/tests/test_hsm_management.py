"""
Test methods for pycryptoki 'hsm management' set of commands.
"""
from ctypes import create_string_buffer, cast
from pycryptoki.cryptoki import CK_ULONG, CK_BYTE, CK_BYTE_PTR
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKU_CRYPTO_USER, CKR_OK, \
    CKR_ATTRIBUTE_VALUE_INVALID, CKR_CANCEL, CKR_USER_NOT_AUTHORIZED, \
    CKA_CLASS, CKO_SECRET_KEY, CKA_KEY_TYPE, CKK_AES, CKA_TOKEN, \
    CKA_SENSITIVE, CKA_PRIVATE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, \
    CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE, CKA_VALUE_LEN, \
    CKA_EXTRACTABLE, CKA_LABEL, LUNA_TTYPE_CRYPTO, LUNA_TTYPE_RNG, \
    LUNA_DSS_SIGVERIFY_TEST
from pycryptoki.default_templates import CKM_RSA_PKCS_KEY_PAIR_GEN, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
from pycryptoki.hsm_management import c_performselftest, \
    ca_settokencertificatesignature, ca_hainit, ca_createloginchallenge, \
    ca_initializeremotepedvector, ca_deleteremotepedvector, ca_mtkrestore, \
    ca_mtkresplit, ca_mtkzeroize
from pycryptoki.key_generator import c_generate_key_pair
import logging
import os
import pytest


class TestAlgorithm:
    """Test algorithm class"""
    h_session = 0
    admin_slot = 0

    @classmethod
    def setup_class(cls):
        """Setup class"""
        setup_for_tests(True, True, True)
        c_initialize_ex()

    @classmethod
    def teardown_class(cls):
        """Finalize tests"""
        c_finalize_ex()

    def setup(self):
        """Setup test"""
        self.admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(self.h_session, self.admin_slot, CO_PASSWORD, CKU_USER)

    def teardown(self):
        """Teardown test"""
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)


    @pytest.mark.parametrize("test_type",
                             [LUNA_TTYPE_CRYPTO,
                              LUNA_TTYPE_RNG,
                              LUNA_DSS_SIGVERIFY_TEST])
    def test_performselftest(self, test_type):
        """Tests performs self test

        :param test_type: test type

        """
        input_data = (CK_BYTE*1000)()
        input_length = CK_ULONG(1000)

        ret = c_performselftest(self.admin_slot,
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
        gen_temp = {CKA_CLASS : CKO_SECRET_KEY,
                    CKA_KEY_TYPE :  CKK_AES,
                    CKA_TOKEN :     True,
                    CKA_SENSITIVE : True,
                    CKA_PRIVATE :   True,
                    CKA_ENCRYPT :   True,
                    CKA_DECRYPT :   True,
                    CKA_SIGN :      True,
                    CKA_VERIFY :    True,
                    CKA_WRAP :      True,
                    CKA_UNWRAP :    True,
                    CKA_DERIVE :    True,
                    CKA_VALUE_LEN : 16,
                    CKA_EXTRACTABLE :True,
                    CKA_LABEL :     "AES Key"}

        access_level = CK_ULONG(1)
        customer_id = CK_ULONG(1)
        pub_template = gen_temp
        signature = (CK_BYTE*4000)()
        signature_length = CK_ULONG(4000)

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


    def test_createloginchallenge(self):
        """Test create login challenge.
        This test requires PED based HSM.
        If performing this test on PWD based HSM return value is CKR_CANCEL.


        """
        user_type = CKU_CRYPTO_USER
        challenge = cast(create_string_buffer("password1234", 12), CK_BYTE_PTR)

        ret = ca_createloginchallenge(self.h_session,
                                      user_type,
                                      challenge)
        assert (ret == CKR_OK or ret == CKR_CANCEL), \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]


    def test_initializeremotepedvector(self):
        """Tests to initialize remote ped vector"""
        ret = ca_initializeremotepedvector(self.h_session)
        # since not SO return value must be CKR_USER_NOT_AUTHORIZED
        assert ret == CKR_USER_NOT_AUTHORIZED, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]


    def test_deleteremotepedvector(self):
        """Tests to delete remote ped vector"""
        ret = ca_deleteremotepedvector(self.h_session)
        # since not SO return value must be CKR_USER_NOT_AUTHORIZED
        assert ret == CKR_USER_NOT_AUTHORIZED, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
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


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
