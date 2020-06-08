"""
Diffie-Hellman mechanisms. 
"""
from _ctypes import pointer, sizeof
from ctypes import cast, c_void_p

from ..attributes import to_byte_array
from ..cryptoki import CK_ECDH1_DERIVE_PARAMS, CK_BYTE_PTR, CK_ULONG
from .helpers import Mechanism


class ECDH1DeriveMechanism(Mechanism):
    """
    ECDH1-specific mechanism
    """

    REQUIRED_PARAMS = ["kdf", "sharedData", "publicData"]

    def to_c_mech(self):
        """
        Create the Param structure, then convert the data into byte arrays.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(ECDH1DeriveMechanism, self).to_c_mech()
        params = CK_ECDH1_DERIVE_PARAMS()
        params.kdf = self.params["kdf"]
        if self.params["sharedData"] is None:
            shared_data = None
            shared_data_len = 0
        else:
            shared_data, shared_data_len = to_byte_array(self.params["sharedData"])
        params.pSharedData = cast(shared_data, CK_BYTE_PTR)
        params.ulSharedDataLen = shared_data_len
        public_data, public_data_len = to_byte_array(self.params["publicData"])
        params.pPublicData = cast(public_data, CK_BYTE_PTR)
        params.ulPublicDataLen = public_data_len
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech
