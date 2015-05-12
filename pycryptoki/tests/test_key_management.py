"""
Test methods for pycryptoki 'key management' set of commands.
"""
from pycryptoki.cryptoki import CK_ULONG, CK_BYTE, CA_MOFN_GENERATION, \
    CA_MOFN_GENERATION_PTR
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKR_OK, CKR_USER_NOT_AUTHORIZED, \
    CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_INCREMENT, \
    CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_SET
from pycryptoki.default_templates import CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
from pycryptoki.key_management import ca_generatemofn, ca_modifyusagecount
from pycryptoki.key_generator import c_generate_key
import logging
import os
import pytest


class TestAlgorithm():
    """ Test algorithm class """
    h_session = 0
    admin_slot = 0

    @classmethod
    def setup_class(self):
        """ Setup class """
        setup_for_tests(True, True, True)
        c_initialize_ex()

    @classmethod
    def teardown_class(self):
        """ Finalize tests """
        c_finalize_ex()

    def setup(self):
        """ Setup test """
        self.admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(self.h_session, self.admin_slot, CO_PASSWORD, CKU_USER)

    def teardown(self):
        """ Teardown test """
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)


    def test_generatemofn(self):
        '''
        Test generate M of N
        '''
        m_value = CK_ULONG(1)
        value = (CK_BYTE*16)()
        vector_count = CK_ULONG(2)
        vector = (CA_MOFN_GENERATION*2)()
        vector[0].ulWeight = CK_ULONG(1)
        vector[0].pVector = value
        vector[0].ulVectorLen = CK_ULONG(16)
        vector[1].ulWeight = CK_ULONG(1)
        vector[1].pVector = (CK_BYTE*16)()
        vector[1].ulVectorLen = CK_ULONG(16)
        vectors = CA_MOFN_GENERATION_PTR(vector)
        is_secure_port_used = CK_ULONG(0)

        ret = ca_generatemofn(self.h_session,
                              m_value,
                              vectors,
                              vector_count,
                              is_secure_port_used)
        assert ret == CKR_USER_NOT_AUTHORIZED, \
            "Return code should be " + \
            ret_vals_dictionary[CKR_USER_NOT_AUTHORIZED] + \
            " not " + ret_vals_dictionary[ret]


    @pytest.mark.parametrize("command_type",
        [CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_INCREMENT,
         CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_SET])
    def test_modifyusagecount(self, command_type):
        '''
        Test modify usage count
        '''
        ret, key_handle = c_generate_key(self.h_session,
                                         CKM_DES_KEY_GEN,
                                         CKM_DES_KEY_GEN_TEMP)
        assert ret == CKR_OK, "Return code should be " + \
            ret_vals_dictionary[CKR_OK] + " not " + ret_vals_dictionary[ret]
        assert key_handle > 0, "The key handle returned should be non zero"

        value = CK_ULONG(0)

        ret = ca_modifyusagecount(self.h_session,
                                  key_handle,
                                  command_type,
                                  value)
        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
