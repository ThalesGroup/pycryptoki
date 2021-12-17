# coding=utf-8
"""
Testcases for string helpers
"""
import datetime
import sys

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
    CKM_RSA_PKCS_PSS,
    CKA_START_DATE,
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


CBC_OUT = """Iv16Mechanism(mech_type: CKM_AES_CBC (0x00001082),
              iv: [0, 1, 2, 3, 4, 5, 6, 7])"""


@pytest.mark.parametrize(
    "mech,output",
    [
        ({"mech_type": CKM_DES_ECB}, "NullMech(mech_type: CKM_DES_ECB (0x00000121))"),
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
            "mechanism: \n\tIvMechanism(mech_type: CKM_AES_CBC (0x00001082))",
        ),
        (
            {
                "wrapped_key": b"\n\xd7\x04R\xd5OufU\x15\x19\xf4\x93\x94\x05\xec\xf9b\x92\xb5,\xa75NM\x93\x14\xeb\xdd\x97\xe0\x8a\xe6\x15w\x86\xe9\x12mu\xb5l\x80QG\x852$X!\xf3H\x05+\xff\xc6j\xa7\x14\xf9\xdb\x1b\n\xd3",
            },
            "wrapped_key: 0ad70452d54f7566551519f4939405ecf96292b5[...] (len: 64)",
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
            "public_template: \n\tCKA_PRIME: [244, 136, 253, 88, 78, 73, 219, 205, 32[...] (len: 128)",
        ),
        (
            {"find_template": {CKA_START_DATE: b"20010101"}},
            "find_template: \n\tCKA_START_DATE: 20010101",
        ),
        pytest.param(
            {"find_template": {CKA_START_DATE: {"year": b"2001", "month": b"01", "day": b"01"}}},
            "find_template: \n\tCKA_START_DATE: {'year': b'2001', 'month': b'01', 'day':[...] (len: 3)",
            marks=pytest.mark.xfail(
                sys.version_info < (3, 0), reason='Byte printing returns b"" in py3, "" in py2'
            ),
        ),
        (
            {"find_template": {CKA_START_DATE: "20010101"}},
            "find_template: \n\tCKA_START_DATE: 20010101",
        ),
        (
            # TODO: Note the formatting difference between datetime.date() & other date formats
            #  To me, this is not ideal. I'd prefer them to be identical. However, fixing that would require
            #  significant changes to how we log/output template data. I do think that it would be a good change,
            #  but it's far more effort than I want to put in right now, as this change is fixing a bug where we
            #  would error on *logging* what we're trying to do.
            {"find_template": {CKA_START_DATE: datetime.date(2001, 1, 1)}},
            "find_template: \n\tCKA_START_DATE: 2001-01-01",
        ),
    ],
    ids=[
        "Mechanism",
        "Invalid UTF8 (binary data)",
        "Template",
        "password",
        "ouid template",
        "long template value",
        "date format, in bytes",
        "date format, in dict",
        "date format, in str",
        "date format, in date obj",
    ],
)
def test_arg_formatting(testargs, expected_result):
    result = pformat_pyc_args(testargs)
    assert expected_result in "\n".join(result)


def test_incomplete_mech():
    kwargs = {"mechanism": CKM_RSA_PKCS_PSS}
    assert "mechanism: \n\tCKM_RSA_PKCS_PSS" in "\n".join(pformat_pyc_args(kwargs))
