"""
DES3-specific mechanism implementations.
"""
import logging
from ctypes import c_void_p, cast, pointer, sizeof

from . import Mechanism
from ..cryptoki import CK_ULONG, CK_BYTE, CK_BYTE_PTR, CK_DES_CTR_PARAMS

LOG = logging.getLogger(__name__)

class DES3CTRMechanism(Mechanism):
    """
    DES3 CTR Mechanism param conversion.


    """

    REQUIRED_PARAMS = ['cb', 'ulCounterBits']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(DES3CTRMechanism, self).to_c_mech()
        ctr_params = CK_DES_CTR_PARAMS()
        ctr_params.cb = (CK_BYTE * 8)(*self.params['cb'])
        ctr_params.ulCounterBits = CK_ULONG(self.params['ulCounterBits'])
        self.mech.pParameter = cast(pointer(ctr_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(ctr_params))
        return self.mech