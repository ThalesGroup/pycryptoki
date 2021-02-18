"""
Testcases for string helpers
"""
import os

import pytest
from pycryptoki.mechanism import Mechanism, IvMechanism

from pycryptoki.defines import CKM_DES_ECB, CKM_AES_CBC, CKA_DECRYPT
from pycryptoki.string_helpers import _decode, _coerce_mech_to_str, pformat_pyc_args


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


@pytest.mark.parametrize(
    "testargs,expected_result",
    [
        (
            {"mechanism": IvMechanism(mech_type=CKM_AES_CBC)},
            "IvMechanism(mech_type: CKM_AES_CBC)",
        ),
        (
            {
                "wrapped_key": b"\n\xd7\x04R\xd5OufU\x15\x19\xf4\x93\x94\x05\xec\xf9b\x92\xb5,\xa75NM\x93\x14\xeb\xdd\x97\xe0\x8a\xe6\x15w\x86\xe9\x12mu\xb5l\x80QG\x852$X!\xf3H\x05+\xff\xc6j\xa7\x14\xf9\xdb\x1b\n\xd3",
            },
            "wrapped_key: 0ad70452d54f75665515[...]ffc66aa714f9db1b0ad3",
        ),
        (
            {"template": {CKA_DECRYPT: True, 0x80000111: True}},
            "CKA_DECRYPT: True\n\t\t0x80000111: True",
        ),
        ({"password": "badpassword"}, "password: *"),
    ],
    ids=["Mechanism", "Invalid UTF8 (binary data)", "Template", "password"],
)
def test_arg_formatting(testargs, expected_result):
    result = pformat_pyc_args(testargs)
    assert expected_result in result
