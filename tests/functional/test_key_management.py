"""
Test methods for pycryptoki 'key management' set of commands.
"""

import pytest

from pycryptoki.default_templates import CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP
from pycryptoki.defines import CKR_OK, CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_INCREMENT, \
    CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_SET
from pycryptoki.key_generator import c_destroy_object, c_generate_key_ex
from pycryptoki.key_management import ca_modifyusagecount
from pycryptoki.lookup_dicts import ret_vals_dictionary
from . import config as hsm_config
from .util import get_session_template

class TestKeyManagementFunctions(object):
    """Test algorithm class"""

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config["test_slot"]

    @pytest.mark.parametrize("command_type",
                             [CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_INCREMENT,
                              CK_MODIFY_USAGE_COUNT_COMMAND_TYPE_SET])
    def test_modifyusagecount(self, command_type):
        """Test modify usage count

        :param command_type:

        """
        key_handle = c_generate_key_ex(self.h_session,
                                       CKM_DES_KEY_GEN,
                                       get_session_template(CKM_DES_KEY_GEN_TEMP))
        try:
            ret = ca_modifyusagecount(self.h_session,
                                      key_handle,
                                      command_type,
                                      0)
            assert ret == CKR_OK, \
                "Return code should be " + ret_vals_dictionary[CKR_OK] + \
                " not " + ret_vals_dictionary[ret]
        finally:
            c_destroy_object(self.h_session, key_handle)
