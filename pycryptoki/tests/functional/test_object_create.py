import logging
import os

import pytest

from . import config as hsm_config
from ...default_templates import CERTIFICATE_TEMPLATE, DATA_TEMPLATE
from ...defines import CKR_OK
from ...misc import c_create_object
from ...return_values import ret_vals_dictionary
from ...test_functions import verify_object_attributes

logger = logging.getLogger(__name__)


@pytest.mark.xfail("Waiting on LA-1860")
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


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
