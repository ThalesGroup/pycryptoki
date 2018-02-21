"""
Tests session management functions
"""
import pytest
import logging

from six import integer_types

from . import config as hsm_config
from pycryptoki.defines import CKR_OK
import pycryptoki.session_management as sess_mang

logger = logging.getLogger(__name__)


class TestSessionManagement(object):
    """
    Tests session management functions
    """
    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.admin_slot = hsm_config["test_slot"]
        self.h_session = auth_session

    def test_c_get_session_info(self):
        """ c_get_session_info() """
        ret, sess_info = sess_mang.c_get_session_info(self.h_session)
        assert ret == CKR_OK
        # Checks that session_info dictionary is the right format. Does not check the values
        assert isinstance(sess_info['state'], integer_types)
        assert isinstance(sess_info['flags'], integer_types)
        assert isinstance(sess_info['slotID'], integer_types)
        assert isinstance(sess_info['usDeviceError'], integer_types)

    def test_get_slot_dict(self):
        """ get_slot_dict() """
        ret, slot_dict = sess_mang.get_slot_dict()
        logger.debug("Slots: %s", slot_dict)
        assert ret == CKR_OK
        assert isinstance(slot_dict, dict)

    def test_get_slot_dict_token_present(self):
        """
        Verify this also works with token_present = True
        """
        slot_dict = sess_mang.get_slot_dict_ex(token_present=True)
        for slot in slot_dict.keys():
            assert sess_mang.c_get_token_info(slot)[0] == CKR_OK

    def test_get_slot_list(self):
        """
        Verify get slot list works as expected.
        """
        slot_list = sess_mang.c_get_slot_list_ex(token_present=True)
        for slot in slot_list:
            assert isinstance(slot, integer_types)
            assert sess_mang.c_get_token_info(slot)[0] == CKR_OK
