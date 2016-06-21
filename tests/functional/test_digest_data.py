import logging

import pytest

from pycryptoki.return_values import ret_vals_dictionary
from . import config as hsm_config
from pycryptoki.defines import CKM_MD2, CKR_OK
from pycryptoki.encryption import _get_string_from_list
from pycryptoki.misc import c_digest

logger = logging.getLogger(__name__)


class TestDigestData(object):
    """ """

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.admin_slot = hsm_config["test_slot"]
        self.h_session = auth_session

    def test_digest_data(self):
        """Calls C_Digest on some data and makes sure there is no failure"""
        data_to_digest = b"Some arbitrary string"
        ret, digested_data = c_digest(self.h_session, data_to_digest, CKM_MD2)
        assert ret == CKR_OK, "Digesting should occur with no errors, got {}".format(ret_vals_dictionary[ret])
        assert len(digested_data) > 0, "The digested data should have a length"
        assert data_to_digest != digested_data, "The digested data should not be the same as the " \
                                                "original string"

    def test_multipart_digest_data(self):
        """ """
        data_to_digest = [b"Some arbitrary string", b"Some second arbitrary string"]
        ret, digested_data = c_digest(self.h_session, data_to_digest, CKM_MD2)
        assert ret == CKR_OK, "Digesting should occur with no errors"
        assert len(digested_data) > 0, "The digested data should have a length"
        assert _get_string_from_list(
            data_to_digest) != digested_data, "The digested data should not be the same as the " \
                                              "original string"
