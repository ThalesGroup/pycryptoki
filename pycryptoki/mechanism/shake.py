"""
Shake Mechanism implementations.
"""
from ctypes import c_void_p, cast, pointer, sizeof

from .helpers import Mechanism
from ..cryptoki import CK_ULONG, CK_SHAKE_PARAMS
from ..defines import *


class ShakeMechanism(Mechanism):
    """
    Create the required CK_SHAKE_PARAMS param structure & convert python data to
    C data.
    """

    REQUIRED_PARAMS = ["outputLen"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(ShakeMechanism, self).to_c_mech()
        shake_params = CK_SHAKE_PARAMS()
        shake_params.ulOutputLen = CK_ULONG(self.params["outputLen"])

        self.mech.pParameter = cast(pointer(shake_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(shake_params))
        return self.mech
