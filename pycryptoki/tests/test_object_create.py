from pycryptoki.default_templates import CERTIFICATE_TEMPLATE, DATA_TEMPLATE
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKR_OK
from pycryptoki.misc import c_create_object
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.test_functions import verify_object_attributes
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
import logging
import os
import pytest

logger = logging.getLogger(__name__)

class TestObjectCloning:
    """ """
    @classmethod
    def setup_class(cls):
        """ """
        setup_for_tests(True, True, True)
        c_initialize_ex()

    @classmethod
    def teardown_class(cls):
        """ """
        c_finalize_ex()

    def setup(self):
        """ """
        admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=admin_slot)
        login_ex(self.h_session, admin_slot, CO_PASSWORD, CKU_USER)

    def teardown(self):
        """ """
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)

    def test_certificate_create(self):
        """Tests C_CreateObject with a certificate template and verifies the object's
        attributes


        """

        ret, h_object = c_create_object(self.h_session, CERTIFICATE_TEMPLATE)
        assert ret == CKR_OK, "The result code of creating a certificate should be CKR_OK, not " + ret_vals_dictionary[ret]

        verify_object_attributes(self.h_session, h_object, CERTIFICATE_TEMPLATE)

    def test_data_create(self):
        """Tests C_CreateObject with a data template and verifies the object's
        attributes


        """
        ret, h_object = c_create_object(self.h_session, DATA_TEMPLATE)
        assert ret == CKR_OK, "The result of creating a data object should be CKR_OK, not" + ret_vals_dictionary[ret]

        verify_object_attributes(self.h_session, h_object, DATA_TEMPLATE)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
