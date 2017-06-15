"""
Testcases for object creation
"""

import logging

import pytest
from pycryptoki.key_generator import c_destroy_object

from pycryptoki.defines import CKA_VALUE

from pycryptoki.object_attr_lookup import c_get_attribute_value_ex

from pycryptoki.default_templates import CERTIFICATE_TEMPLATE, DATA_TEMPLATE
from pycryptoki.misc import c_create_object_ex
from . import config as hsm_config
from .util import get_session_template

logger = logging.getLogger(__name__)


class TestObjectCreation(object):
    """Tests certificate & data creation."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config["test_slot"]

    def test_certificate_create(self):
        """Tests C_CreateObject with a certificate template and verifies the object's
        attributes


        """
        template = get_session_template(CERTIFICATE_TEMPLATE)
        h_object = c_create_object_ex(self.h_session, template)
        try:
            desired_attrs = {x: None for x in template.keys()}
            attr = c_get_attribute_value_ex(self.h_session, h_object, template=desired_attrs)
            # CKA_VALUE in the template is a list of ints, but is returned as a single hex string.
            # Let's try to convert it back to the list of ints.
            value = attr[CKA_VALUE]
            attr[CKA_VALUE] = [int(value[x:x+2], 16) for x in range(0, len(value), 2)]
            assert attr == template
        finally:
            c_destroy_object(self.h_session, h_object)

    def test_data_create(self):
        """Tests C_CreateObject with a data template and verifies the object's
        attributes


        """
        template = get_session_template(DATA_TEMPLATE)
        h_object = c_create_object_ex(self.h_session, template)
        try:
            desired_attrs = {x: None for x in template.keys()}
            attr = c_get_attribute_value_ex(self.h_session, h_object, template=desired_attrs)
            # CKA_VALUE in the template is a list of ints, but is returned as a single hex string.
            # Let's try to convert it back to the list of ints.
            value = attr[CKA_VALUE]
            attr[CKA_VALUE] = [int(value[x:x + 2], 16) for x in range(0, len(value), 2)]
            assert attr == template
        finally:
            c_destroy_object(self.h_session, h_object)
