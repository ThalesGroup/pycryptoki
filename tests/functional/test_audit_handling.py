import logging
import pytest

from . import config as hsm_config
from pycryptoki.defines import CKR_OK
import pycryptoki.audit_handling as audit_handling

from ctypes import c_ulong

logger = logging.getLogger(__name__)


class TestAuditHandling(object):
    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.admin_slot = hsm_config["test_slot"]
        self.h_session = auth_session

    def test_ca_get_time(self):
        """ ca_get_time() """
        ret, hsm_time = audit_handling.ca_get_time(self.h_session)
        assert ret == CKR_OK
        # Checks time formatting but not value of returned time
        assert isinstance(hsm_time, c_ulong)
