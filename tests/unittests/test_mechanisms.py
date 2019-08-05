"""
Unittests related to the mechanism module.
"""
import pytest
from ctypes import cast, c_ulong, c_ubyte
from mock import patch
from six import integer_types

from pycryptoki.conversions import from_hex, to_bytestring
from pycryptoki.cryptoki import (
    CK_RSA_PKCS_PSS_PARAMS,
    POINTER,
    CK_ULONG,
    CK_AES_GCM_PARAMS,
    CK_MECHANISM,
)
from pycryptoki.defines import *
from pycryptoki.mechanism import (
    Mechanism,
    MechanismException,
    AutoMech,
    MECH_LOOKUP,
    AESGCMMechanism,
    NullMech,
    EDDSAMechanism,
)

MECH_PARAMS = {
    CKM_AES_XTS: {"hTweakKey": 0, "cb": list(range(12)), "test_id": "AES_XTS"},
    CKM_DES3_CBC: {"iv": list(range(12)), "test_id": "DES3"},
    CKM_AES_CBC: {"iv": list(range(16)), "test_id": "AES_CBC"},
    CKM_RC2_ECB: {"usEffectiveBits": 8, "test_id": "RC2_ECB"},
    CKM_RC2_CBC: {"usEffectiveBits": 8, "iv": list(range(8)), "test_id": "RC2_CBC"},
    CKM_RC5_ECB: {"ulWordsize": 8, "ulRounds": 8, "test_id": "RC5_ECB"},
    CKM_RC5_CBC: {"ulWordsize": 8, "ulRounds": 2, "iv": list(range(12)), "test_id": "RC5_CBC"},
    CKM_RSA_PKCS_OAEP: {
        "hashAlg": CKM_SHA_1,
        "mgf": CKG_MGF1_SHA1,
        "sourceData": list(range(12)),
        "test_id": "RSA_OAEP",
    },
    CKM_AES_GCM: {"iv": list(range(16)), "AAD": b"deadbeef", "ulTagBits": 32, "test_id": "AES_GCM"},
    CKM_RSA_PKCS_PSS: {"hashAlg": CKM_SHA_1, "mgf": CKG_MGF1_SHA1, "test_id": "RSA_PSS"},
}


def idfn(test):
    return MECH_PARAMS[test].get("test_id", "unknown")


# noinspection PyArgumentList
class TestMechanisms(object):
    @pytest.mark.parametrize(
        "flavor,params",
        [
            (CKM_AES_XTS, ["hTweakKey", "cb"]),
            (CKM_RC2_ECB, ["usEffectiveBits"]),
            (CKM_RC2_CBC, ["usEffectiveBits", "iv"]),
            (CKM_RC5_ECB, ["ulWordsize", "ulRounds"]),
            (CKM_RC5_CBC, ["ulWordsize", "ulRounds", "iv"]),
            (CKM_RSA_PKCS_OAEP, ["hashAlg", "mgf"]),
        ],
        ids=["XTS", "RC2", "RC2_CBC", "RC5", "RC5_CBC", "RSA_PKCS_OAEP"],
    )
    def test_missing_params(self, flavor, params):
        """
        Test that missing parameters for various mechs raises the appropriate exception.

        :param crypto_session:
        :return:
        """
        with pytest.raises(MechanismException) as excinfo:
            mech = Mechanism(flavor)

        for x in params:
            assert x in str(excinfo.value)

    def test_auto_mechanism_simple_vals(self):
        """
        Test that a mechanism created via the 'automech' creates a mechanism as expected.

        :return:
        """
        # Patch the mechanism lookup so that we don't have to have an undefined
        # mechanism to test the automech.
        with patch.dict(MECH_LOOKUP, {}, clear=True):
            pymech = AutoMech(
                CKM_RSA_PKCS_PSS,
                params={
                    "params_name": "CK_RSA_PKCS_PSS_PARAMS",
                    "hashAlg": CKM_SHA_1,
                    "mgf": CKG_MGF1_SHA1,
                    "usSaltLen": 8,
                },
            )
            assert isinstance(pymech, AutoMech)
            cmech = pymech.to_c_mech()
            params = cast(cmech.pParameter, POINTER(CK_RSA_PKCS_PSS_PARAMS)).contents
            assert params.hashAlg == CKM_SHA_1
            assert params.mgf == CKG_MGF1_SHA1
            assert params.usSaltLen == 8
            assert isinstance(params.usSaltLen, (integer_types, CK_ULONG))
            assert isinstance(params.hashAlg, (integer_types, CK_ULONG))
            assert isinstance(params.mgf, (integer_types, CK_ULONG))

    def test_null_mechanism_indirect_instantiation(self):
        """
        Test automech by instantiating Mechanism() instead of AutoMech()

        :return:
        """
        # Patch the mechanism lookup so that we don't have to have an undefined
        # mechanism to test the automech.
        with patch.dict(MECH_LOOKUP, {}, clear=True):
            pymech = Mechanism(CKM_RSA_PKCS_PSS)

            assert isinstance(pymech, NullMech)
            cmech = pymech.to_c_mech()
            assert cmech.pParameter is None
            assert cmech.usParameterLen == 0

    def test_exact_mechanism_use(self):
        """
        Test that directly instantiating a subclass of Mechanism works as expected.

        :return:
        """
        mech = AESGCMMechanism(
            mech_type=CKM_AES_GCM,
            params={
                "AAD": to_bytestring(from_hex(b"deadbeef")),
                "iv": list(range(12)),
                "ulTagBits": 32,
            },
        )
        cmech = mech.to_c_mech()
        cparams = cast(cmech.pParameter, POINTER(CK_AES_GCM_PARAMS)).contents
        assert cparams.ulTagBits == 32

    @pytest.mark.parametrize("flavor", list(MECH_PARAMS.keys()), ids=idfn)
    def test_mech_conversions(self, flavor):
        """
        Test that converting each mechanism works as expected w/ valid params.
        """
        params = MECH_PARAMS[flavor]
        mech = Mechanism(flavor, params=params)

        cmech = mech.to_c_mech()
        # Would prefer to check if it's a c_void_p, but it gets transformed directly to
        # an int/long depending on memory location.
        assert isinstance(cmech.pParameter, (integer_types, c_ulong))
        assert isinstance(cmech.usParameterLen, (integer_types, c_ulong))
        assert isinstance(cmech, CK_MECHANISM)
        assert cmech.mechanism == flavor

    def test_default_iv_params(self):
        """
        Verify passing no IV to a mech requiring an IV will use the default value.
        """
        cmech = Mechanism(CKM_DES3_CBC).to_c_mech()

        rawiv = cast(cmech.pParameter, POINTER(c_ubyte))
        iv = [rawiv[x] for x in range(cmech.usParameterLen)]
        assert iv == [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]

    def test_default_iv6_params(self):
        """
        Verify passing no IV to a mech requiring an IV will use the default value.
        """
        cmech = Mechanism(CKM_AES_CBC).to_c_mech()

        rawiv = cast(cmech.pParameter, POINTER(c_ubyte))
        iv = [rawiv[x] for x in range(cmech.usParameterLen)]
        assert iv == [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]

    @pytest.mark.parametrize(
        "flavor",
        [CKM_SHA256, CKM_SHA512, CKM_DSA, CKM_RSA_PKCS],
        ids=["SHA256", "SHA512", "DSA", "RSA_PKCS"],
    )
    def test_null_mech(self, flavor):
        """
        Verify creating a 'null mech' will fill out the parameter fields properly.
        """
        cmech = NullMech(flavor).to_c_mech()

        assert cmech.pParameter is None
        assert cmech.usParameterLen == 0

    def test_no_params_given_automech(self):
        """
        Verify that creating an automech w/o a params_name in the dictionary
        will fail.
        """
        with patch.dict(MECH_LOOKUP, {}, clear=True):
            with pytest.raises(MechanismException) as excinfo:
                cmech = AutoMech(CKM_DES3_CBC).to_c_mech()

            assert "Failed to find a suitable Ctypes Parameter" in str(excinfo.value)

    @pytest.mark.parametrize(
        "mech_type,params",
        [
            (CKM_EDDSA, None),
            (CKM_EDDSA, {"phFlag": True}),
            (CKM_EDDSA_NACL, None),
            (CKM_EDDSA_NACL, {"phFlag": True}),
        ],
    )
    def test_eddsa_mech(self, mech_type, params):
        """Test EDDSAMechanism"""
        mechanism = EDDSAMechanism(mech_type, params)
        mechanism.to_c_mech()
        assert mechanism.mech.mechanism == mech_type
        if params:
            assert mechanism.mech.pParameter
        else:
            assert not mechanism.mech.pParameter
