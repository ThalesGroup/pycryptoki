import logging
import os

import pytest

from . import config as hsm_config
from ...defines import CKM_MD2, CKR_OK
from ...encryption import _get_string_from_list
from ...misc import c_digest

logger = logging.getLogger(__name__)


class TestDigestData(object):
    """ """

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.admin_slot = hsm_config["test_slot"]
        self.h_session = auth_session

    def test_digest_data(self):
        """Calls C_Digest on some data and makes sure there is no failure"""
        data_to_digest = "Some arbitrary string"
        ret, digested_data = c_digest(self.h_session, data_to_digest, CKM_MD2)
        assert ret == CKR_OK, "Digesting should occur with no errors"
        assert len(digested_data) > 0, "The digested data should have a length"
        assert data_to_digest != digested_data, "The digested data should not be the same as the " \
                                                "original string"

    def test_multipart_digest_data(self):
        """ """
        data_to_digest = ["Some arbitrary string", "Some second arbitrary string"]
        ret, digested_data = c_digest(self.h_session, data_to_digest, CKM_MD2)
        assert ret == CKR_OK, "Digesting should occur with no errors"
        assert len(digested_data) > 0, "The digested data should have a length"
        assert _get_string_from_list(
            data_to_digest) != digested_data, "The digested data should not be the same as the " \
                                              "original string"


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-vs', os.path.abspath(__file__)])
