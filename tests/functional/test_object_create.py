import logging

import pytest

from . import config as hsm_config
from pycryptoki.default_templates import CERTIFICATE_TEMPLATE, DATA_TEMPLATE
from pycryptoki.defines import CKR_OK
from pycryptoki.misc import c_create_object
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.test_functions import verify_object_attributes

logger = logging.getLogger(__name__)


@pytest.mark.xfail(reason="Attributes do not convert 1-to-1 back to python")
class TestObjectCloning(object):
    """ """

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config["test_slot"]

    def test_certificate_create(self):
        """Tests C_CreateObject with a certificate template and verifies the object's
        attributes


        """

        ret, h_object = c_create_object(self.h_session, CERTIFICATE_TEMPLATE)
        assert ret == CKR_OK, \
            "The result code of creating a " \
            "certificate should be CKR_OK, not " + ret_vals_dictionary[ret]

        verify_object_attributes(self.h_session, h_object, CERTIFICATE_TEMPLATE)

    def test_data_create(self):
        """Tests C_CreateObject with a data template and verifies the object's
        attributes


        """
        ret, h_object = c_create_object(self.h_session, DATA_TEMPLATE)
        assert ret == CKR_OK, \
            "The result of creating a data object should be CKR_OK, not" + ret_vals_dictionary[ret]

        verify_object_attributes(self.h_session, h_object, DATA_TEMPLATE)

