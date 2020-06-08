"""
Testcases for string helpers
"""
import pytest
from pycryptoki.mechanism import Mechanism

from pycryptoki.defines import CKM_DES_ECB, CKM_AES_CBC
from pycryptoki.string_helpers import _decode, _coerce_mech_to_str


@pytest.mark.parametrize(
    "value,ret",
    [
        (b"this is a test string", u"this is a test string"),
        (b"\x01\x23\x82\x20\x01\xb6\x09\xd2\xb6|gN\xcc", u"0123822001b609d2b67c674ecc"),
        (None, None),
        (b"", u""),
    ],
)
def test_decode(value, ret):
    assert _decode(value) == ret


CBC_OUT = """Iv16Mechanism(mech_type: CKM_AES_CBC,
              iv: [0, 1, 2, 3, 4, 5, 6, 7])"""


@pytest.mark.parametrize(
    "mech,output",
    [
        ({"mech_type": CKM_DES_ECB}, "NullMech(mech_type: CKM_DES_ECB)"),
        (Mechanism(CKM_AES_CBC, params={"iv": list(range(8))}), CBC_OUT),
    ],
)
def test_mech_printing(mech, output):
    assert _coerce_mech_to_str(mech) == output
