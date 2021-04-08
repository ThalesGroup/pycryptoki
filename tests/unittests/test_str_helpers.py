# coding=utf-8
"""
Testcases for string helpers
"""

import pytest
from hypothesis import given, strategies, example

from pycryptoki.default_templates import dh_prime
from pycryptoki.mechanism import Mechanism, IvMechanism

from pycryptoki.defines import (
    CKM_DES_ECB,
    CKM_AES_CBC,
    CKA_DECRYPT,
    CKA_OUID,
    CKA_PRIME,
    CKA_KEY_TYPE,
)
from pycryptoki.string_helpers import _decode, _coerce_mech_to_str, pformat_pyc_args


@pytest.mark.parametrize(
    "value,ret",
    [
        (b"this is a test string", b"this is a test string"),
        (b"\x01\x23\x82\x20\x01\xb6\x09\xd2\xb6|gN\xcc", "0123822001b609d2b67c674ecc"),
        (None, None),
        (b"", ""),
    ],
)
def test_decode(value, ret):
    assert _decode(value) == ret


@given(strategies.binary())
# Explicit example from a failing test in live -- has a unicode character that will fail on a str() call in python2
@example(u" SxҎTmi".encode("utf-8"))
def test_fuzzed_decoding(bdata):
    # raises if we couldn't call str() on the results
    pformat_pyc_args({"data": bdata})


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
            "mechanism: \n\tIvMechanism(mech_type: CKM_AES_CBC)",
        ),
        (
            {
                "wrapped_key": b"\n\xd7\x04R\xd5OufU\x15\x19\xf4\x93\x94\x05\xec\xf9b\x92\xb5,\xa75NM\x93\x14\xeb\xdd\x97\xe0\x8a\xe6\x15w\x86\xe9\x12mu\xb5l\x80QG\x852$X!\xf3H\x05+\xff\xc6j\xa7\x14\xf9\xdb\x1b\n\xd3",
            },
            "wrapped_key: 0ad70452d54f75665515[...]ffc66aa714f9db1b0ad3",
        ),
        (
            {"template": {CKA_DECRYPT: True, 0x80000111: True, CKA_KEY_TYPE: 0}},
            "\n\tCKA_DECRYPT: True\n\t0x80000111: True",
        ),
        ({"password": "badpassword"}, "password: *"),
        (
            {"template": {CKA_OUID: b"005211001100000128230900"}},
            "template: \n\tCKA_OUID: 005211001100000128230900",
        ),
        (
            {"public_template": {CKA_PRIME: dh_prime}},
            "public_template: \n\tCKA_PRIME: [244, 136, 253, 88, [...], 233, 47, 120, 199]",
        ),
    ],
    ids=[
        "Mechanism",
        "Invalid UTF8 (binary data)",
        "Template",
        "password",
        "ouid template",
        "long template value",
    ],
)
def test_arg_formatting(testargs, expected_result):
    result = pformat_pyc_args(testargs)
    assert expected_result in "\n".join(result)
