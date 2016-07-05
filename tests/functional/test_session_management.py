import pytest
import logging

from . import config as hsm_config
from pycryptoki.defines import CKR_OK
import pycryptoki.session_management as sess_mang

logger = logging.getLogger(__name__)


class TestSessionManagement(object):

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.admin_slot = hsm_config["test_slot"]
        self.h_session = auth_session

    def test_c_get_session_info(self):
        """ c_get_session_info() """
        ret, sess_info = sess_mang.c_get_session_info(self.h_session)
        assert ret == CKR_OK
        # Checks that session_info dictionary is the right format. Does not check the values
        assert isinstance(sess_info['state'], long)
        assert isinstance(sess_info['flags'], long)
        assert isinstance(sess_info['slotID'], long)
        assert isinstance(sess_info['usDeviceError'], long)

    def test_get_slot_dict(self):
        """ get_slot_dict() """
        ret, slot_dict = sess_mang.get_slot_dict()
        assert ret == CKR_OK
        assert isinstance(slot_dict, dict)
