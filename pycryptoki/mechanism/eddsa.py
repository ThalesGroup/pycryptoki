"""
Edwards EC-specific mechanism implementation. Params are optional.
"""
from ctypes import c_void_p, cast, pointer, sizeof


from . import Mechanism, MechanismException
from ..attributes import to_byte_array
from ..cryptoki import CK_BBOOL, CK_ULONG, CK_BYTE_PTR, CK_EDDSA_PARAMS


class EDDSAMechanism(Mechanism):
    """
    Mech class for EDDSA.

    Luna Docs indicate that parameters are optional. The use of the pre-hashed
    ed25519ph curve variant is controlled by the phFlag value in the parameter
    struct. If parameters are not specified, it is the same as setting phFlag
    false; the regular ed25519 curve variant will be used.
    """

    OPTIONAL_PARAMS = ["phFlag", "ContextData"]

    def to_c_mech(self):
        super(EDDSAMechanism, self).to_c_mech()

        if not self.params:
            self.mech.pParameter = c_void_p(0)
            self.mech.usParameterLen = CK_ULONG(0)
            return self.mech

        ph_flag = self.params.get("phFlag", None)
        if ph_flag is None:
            # if params were specified, phFlag is required
            raise MechanismException(
                "Cannot create {}, Missing required parameters:\n\t{}".format(
                    self.__class__, "phFlag"
                )
            )

        params = CK_EDDSA_PARAMS()
        params.phFlag = CK_BBOOL(int(bool(ph_flag)))

        # Luna Docs state pContextData must be null; allow to be optional
        context_data = self.params.get("ContextData", None)
        if context_data is None:
            params.pContextData = None
            length = CK_ULONG(0)
        else:
            context_data, length = to_byte_array(self.params["ContextData"])
            params.pContextData = cast(context_data, CK_BYTE_PTR)
        params.ulContextDataLen = length
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech
