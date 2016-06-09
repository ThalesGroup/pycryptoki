"""
Test methods for pycryptoki 'key management' set of commands.
"""
import logging
import os

import pytest

from . import config as hsm_config
from ...cryptoki import CK_ULONG, CK_BYTE, CA_MOFN_GENERATION, \
    CA_MOFN_GENERATION_PTR
from ...default_templates import CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP
from ...defines import CKR_OK, CKR_USER_NOT_AUTHORIZED, \
    CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_INCREMENT, \
    CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_SET
from ...key_generator import c_generate_key
from ...key_management import ca_generatemofn, ca_modifyusagecount
from ...return_values import ret_vals_dictionary


class TestAlgorithm(object):
    """Test algorithm class"""
    h_session = 0
    admin_slot = 0

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config["test_slot"]

    @pytest.mark.xfail(run=False)
    def test_generatemofn(self):
        """Test generate M of N"""
        m_value = CK_ULONG(1)
        value = (CK_BYTE * 16)()
        vector_count = CK_ULONG(2)
        vector = (CA_MOFN_GENERATION * 2)()
        vector[0].ulWeight = CK_ULONG(1)
        vector[0].pVector = value
        vector[0].ulVectorLen = CK_ULONG(16)
        vector[1].ulWeight = CK_ULONG(1)
        vector[1].pVector = (CK_BYTE * 16)()
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
        """Test modify usage count

        :param command_type:

        """
        ret, key_handle = c_generate_key(self.h_session,
                                         CKM_DES_KEY_GEN,
                                         CKM_DES_KEY_GEN_TEMP)
        assert ret == CKR_OK, "Return code should be " + \
                              ret_vals_dictionary[CKR_OK] + " not " + ret_vals_dictionary[ret]
        assert key_handle > 0, "The key handle returned should be non zero"

        ret = ca_modifyusagecount(self.h_session,
                                  key_handle,
                                  command_type,
                                  0)
        assert ret == CKR_OK, \
            "Return code should be " + ret_vals_dictionary[CKR_OK] + \
            " not " + ret_vals_dictionary[ret]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
