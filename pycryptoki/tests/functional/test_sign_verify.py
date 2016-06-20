import logging

import pytest

from . import config as hsm_config
from ...default_templates import CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, \
    CKM_DSA_KEY_PAIR_GEN_PRIVTEMP, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224, \
    CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256
from ...defines import CKR_OK, CKM_RSA_PKCS, \
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN, CKM_DSA
from ...key_generator import c_generate_key_pair_ex
from ...return_values import ret_vals_dictionary
from ...sign_verify import c_sign, c_verify

logger = logging.getLogger(__name__)


class TestSignVerify(object):
    """ """

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config["test_slot"]

    @pytest.mark.parametrize(("key_type", "pub_key_template", "priv_key_template", "sign_flavor"), [
        pytest.mark.xfail(reason="Data len failure")((CKM_RSA_PKCS_KEY_PAIR_GEN,
                                                      CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                                                      CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP,
                                                      CKM_RSA_PKCS)),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA)
    ])
    def test_sign_verify(self, key_type, pub_key_template, priv_key_template, sign_flavor):
        """Verifies that signing a string and verifying that string works

        :param key_type: The handle of the key to sign the data with
        :param pub_key_template: The template for the public key to be generated
        :param priv_key_template: The template for the private key to be generated
        :param sign_flavor: The flavor of the signature

        """

        # Generate a key for the test
        h_pub_key, h_priv_key = c_generate_key_pair_ex(self.h_session, key_type, pub_key_template,
                                                       priv_key_template)

        data_to_sign = "This is some test string to sign."
        ret, signature = c_sign(self.h_session, sign_flavor, data_to_sign, h_priv_key)
        assert ret == CKR_OK, "The result code of the sign operation should be CKR_OK not " + \
                              ret_vals_dictionary[ret]

        ret = c_verify(self.h_session, h_pub_key, sign_flavor, data_to_sign, signature)
        assert ret == CKR_OK, "The result code of the verify operation should be CKR_OK not " + \
                              ret_vals_dictionary[ret]

    @pytest.mark.parametrize(("key_type", "pub_key_template", "priv_key_template", "sign_flavor"), [
        (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA),
        (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA),
        (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA),
        (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
         CKM_DSA)
    ])
    def test_multipart_sign_verify(self, key_type, pub_key_template, priv_key_template,
                                   sign_flavor):
        """Verifies that signing a string and verifying that string works doing the operation
        in multiple parts with c_sign_update and c_verify_update

        :param key_type: The handle of the key to sign the data with
        :param pub_key_template: The template for the public key to be generated
        :param priv_key_template: The template for the private key to be generated
        :param sign_flavor: The flavor of the signature

        """

        # Generate a key for the test
        h_pub_key, h_priv_key = c_generate_key_pair_ex(self.h_session, key_type, pub_key_template,
                                                       priv_key_template)

        data_to_sign = ["a" * 1024, "b" * 1024]
        ret, signature = c_sign(self.h_session, sign_flavor, data_to_sign, h_priv_key)
        assert ret == CKR_OK, "The result code of the sign operation should be CKR_OK not " + \
                              ret_vals_dictionary[ret]

        ret = c_verify(self.h_session, h_pub_key, sign_flavor, data_to_sign, signature)
        assert ret == CKR_OK, "The result code of the verify operation should be CKR_OK not " + \
                              ret_vals_dictionary[ret]
