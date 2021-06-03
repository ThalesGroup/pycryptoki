""" Functional tests for digest data """
import logging
import pytest

from pycryptoki.lookup_dicts import ret_vals_dictionary
from pycryptoki.defines import (
    CKR_OK,
    CKM_MD2,
    CKM_SHA_1,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
)
from pycryptoki.misc import c_digest

logger = logging.getLogger(__name__)

MECHS = {
    CKM_MD2: "MD2",
    CKM_SHA_1: "SHA1",
    CKM_SHA224: "SHA224",
    CKM_SHA256: "SHA256",
    CKM_SHA384: "SHA384",
    CKM_SHA512: "SHA512",
}

DATA = [b"Some arbitrary string", [b"Some arbitrary string", b"Some second arbitrary string"]]


class TestDigestData(object):
    def verify_ret(self, ret, expected_ret):
        """
        Assert that ret is as expected
        :param ret: the actual return value
        :param expected_ret: the expected return value
        """
        assert ret == expected_ret, (
            "Function should return: "
            + ret_vals_dictionary[expected_ret]
            + ".\nInstead returned: "
            + ret_vals_dictionary[ret]
        )

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session

    @pytest.mark.parametrize("data", DATA, ids=["String", "Blocks"])
    @pytest.mark.parametrize("mech", list(MECHS.keys()), ids=list(MECHS.values()))
    def test_digest_data(self, mech, data):
        """
        Tests digest data mechs
        :param mech: parametrized mech from 'MECHS'
        :param data: parametrized testing data from 'DATA'
        """
        ret, digested_data = c_digest(self.h_session, data, mech)
        self.verify_ret(ret, CKR_OK)
        assert len(digested_data) > 0, "The digested data should have a length"
        assert data != digested_data, "Digested data should not be the same as the original string"
