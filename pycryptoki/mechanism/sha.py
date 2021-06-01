"""
Sha Hmac General Mechanism implementations.
"""
from ctypes import c_void_p, cast, pointer, sizeof

from .helpers import Mechanism
from ..cryptoki import CK_ULONG, CK_SHA_HMAC_GENERAL_PARAMS
from ..defines import *


class ShaHmacGeneralMechanism(Mechanism):
    """
    Create the required CK_SHA_HMAC_GENERAL_PARAMS param structure & convert python data to
    C data.
    """

    REQUIRED_PARAMS = ["outputLen"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(ShaHmacGeneralMechanism, self).to_c_mech()
        sha_params = CK_SHA_HMAC_GENERAL_PARAMS()
        sha_params.ulOutputLen = CK_ULONG(self.params["outputLen"])

        self.mech.pParameter = cast(pointer(sha_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(sha_params))
        return self.mech
