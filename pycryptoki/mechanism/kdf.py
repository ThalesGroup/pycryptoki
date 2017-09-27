"""KDF-specific mechanism implementations."""

from _ctypes import pointer, sizeof
from ctypes import cast, c_void_p

from . import Mechanism
from ..attributes import to_byte_array
from ..cryptoki import CK_PRF_KDF_PARAMS, CK_BYTE_PTR, CK_ULONG


class PRFKDFDeriveMechanism(Mechanism):
    """PRF KDF-specific mechanism."""
    REQUIRED_PARAMS = ['prf_type', 'label', 'context', 'counter', 'encoding_scheme']

    def to_c_mech(self):
        """
        Create the Param structure, then convert the data into byte arrays.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`

        """
        super(PRFKDFDeriveMechanism, self).to_c_mech()
        params = CK_PRF_KDF_PARAMS()
        params.prfType = self.params['prf_type']
        if self.params['label'] is None:
            label = ''
            label_len = 0
        else:
            label, label_len = to_byte_array(self.params['label'])
        if self.params['context'] is None:
            context = ''
            context_len = 0
        else:
            context, context_len = to_byte_array(self.params['context'])
        if self.params['counter'] is None:
            counter = 1
        else:
            counter = self.params['counter']
        ul_encoding_scheme = self.params['encoding_scheme']

        params.pLabel = cast(label, CK_BYTE_PTR)
        params.ulLabelLen = label_len
        params.pContext = cast(context, CK_BYTE_PTR)
        params.ulContextLen = context_len
        params.ulCounter = counter
        params.ulEncodingScheme = ul_encoding_scheme
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech
