"""
Testcases for wrapping/unwrapping keys.
"""
import logging
from distutils.version import LooseVersion
from contextlib import contextmanager
import random

import pytest
from _ctypes import POINTER
from ctypes import c_ulong, byref, cast
from pycryptoki.backup import ca_extract, ca_insert
from .cpv4_util import (
    generate_cpv4_extract_mech_params,
    generate_cpv4_insert_mech,
    verify_extracted_objects,
)
from pycryptoki.session_management import c_open_session_ex, login_ex, c_close_session, c_logout
from pycryptoki.cryptoki import CK_BYTE_PTR, CK_CPV4_EXTRACT_PARAMS, CK_CPV4_INSERT_PARAMS
from pycryptoki.ca_extensions.cpv4 import (
    ca_migrate_keys,
    MIGRATION_DATA,
    ca_migration_start_session_negotiation,
    ca_migration_continue_session_negotiation,
    ca_migration_close_session,
)
from pycryptoki.default_templates import (
    get_default_key_template,
    CERTIFICATE_TEMPLATE,
    DATA_TEMPLATE,
    get_default_key_pair_template,
)
from pycryptoki.defines import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKF_CPV4_CONTINUE_ON_ERR,
    CK_CRYPTOKI_ELEMENT,
    CKM_DES_ECB,
    CKM_DES_CBC,
    CKM_DES_CBC_PAD,
    CKM_DES_KEY_GEN,
    CKM_DES3_ECB,
    CKM_DES3_CBC,
    CKM_DES3_CBC_PAD,
    CKM_DES3_KEY_GEN,
    CKM_AES_ECB,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_KEY_GEN,
    CKM_CAST3_ECB,
    CKM_CAST3_CBC,
    CKM_CAST3_CBC_PAD,
    CKM_CAST3_KEY_GEN,
    CKM_CAST5_ECB,
    CKM_CAST5_CBC,
    CKM_CAST5_CBC_PAD,
    CKM_CAST5_KEY_GEN,
    CKM_RC4_KEY_GEN,
    CKM_RC2_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_X9_31_KEY_PAIR_GEN,
    CKM_SEED_ECB,
    CKM_SEED_CBC,
    CKM_SEED_KEY_GEN,
    CKR_OK,
    CKA_DECRYPT,
    CKA_VERIFY,
    CKA_UNWRAP,
    CKM_AES_KWP,
    CKA_VALUE_LEN,
    CKA_EXTRACTABLE,
    CKA_OUID,
    CK_NULL_ELEMENT,
    CK_CRYPTOKI_ELEMENT,
    CK_PARAM_ELEMENT,
    CK_CONTAINER_ACTIVATION_ELEMENT,
    CK_MOFN_ACTIVATION_ELEMENT,
    CK_CONTAINER_ELEMENT,
    CKA_TOKEN,
    CKR_INTEGER_OVERFLOW,
    CKR_OBJECT_TYPE_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
)

from pycryptoki.encryption import c_wrap_key, c_unwrap_key, c_encrypt, c_decrypt
from pycryptoki.key_generator import (
    c_destroy_object,
    c_generate_key,
    c_generate_key_ex,
    c_generate_key_pair,
)
from pycryptoki.misc import c_create_object_ex
from pycryptoki.lookup_dicts import ret_vals_dictionary
from pycryptoki.object_attr_lookup import c_get_attribute_value_ex, c_find_objects_ex
from pycryptoki.test_functions import verify_object_attributes
from . import config as hsm_config
from .util import get_session_template

logger = logging.getLogger(__name__)

SYM_KEYS = [
    CKM_DES_KEY_GEN,
    CKM_DES3_KEY_GEN,
    CKM_AES_KEY_GEN,
    CKM_CAST3_KEY_GEN,
    CKM_CAST5_KEY_GEN,
    CKM_SEED_KEY_GEN,
    CKM_RC4_KEY_GEN,
    CKM_RC2_KEY_GEN,
]
ASYM_KEYS = [CKM_RSA_PKCS_KEY_PAIR_GEN]
SYM = "sym"
ASYM = "asym"
DATA = "data"
CERT_DATA = "cert_data"
USER_TYPE = 1
SESSION_FLAGS = CKF_SERIAL_SESSION | CKF_RW_SESSION
INVALID_OBJECTS_TYPES = [
    CK_NULL_ELEMENT,
    CK_PARAM_ELEMENT,
    CK_CONTAINER_ACTIVATION_ELEMENT,
    CK_MOFN_ACTIVATION_ELEMENT,
    CK_CONTAINER_ELEMENT,
]


@contextmanager
def get_co_auth_session(slot, user_pwd):
    """opens a session and logs in as CO"""
    h_session = None
    try:
        h_session = c_open_session_ex(slot, SESSION_FLAGS)
        login_ex(h_session, slot, user_pwd, USER_TYPE)
        yield h_session
    finally:
        if h_session:
            c_logout(h_session)
        c_close_session(slot)


@pytest.fixture(scope="class")
def source_session(hsm_configured):
    """Opens a session for the source partition and logs in"""
    _ = hsm_configured
    slot = hsm_config["test_slot"]
    with get_co_auth_session(slot, hsm_config["password"]) as session:
        yield session


@pytest.fixture(scope="class")
def target_session(hsm_configured):
    """opens a session for target partition and logs in"""
    _ = hsm_configured
    slot = hsm_config["test_clone_slot"]
    with get_co_auth_session(slot, hsm_config["password"]) as session:
        yield session


@contextmanager
def gen_sym_keys(source_session, key_type, num_obj=1):
    """ Fixture containing keys"""
    keys = []
    try:
        for _ in range(num_obj):
            template = get_default_key_template(key_type)
            ret, key_handle = c_generate_key(source_session, key_type, template)
            if ret == CKR_OK:
                keys.append(key_handle)
            else:
                logger.info("Failed to generate key: {}\nReturn code: {}".format(key_type, ret))
        yield keys
    finally:
        destroy_objects(source_session, keys)


@contextmanager
def gen_asym_keys(source_session, key_type, num_obj=1):
    """ Fixture containing all asym. keys """
    keys = []
    try:
        for _ in range(num_obj):
            pub_temp, prv_temp = get_default_key_pair_template(key_type)

            ret, pub_key, prv_key = c_generate_key_pair(
                source_session, key_type, pub_temp, prv_temp
            )
            if ret == CKR_OK:
                keys += [pub_key, prv_key]
            else:
                logger.info("Failed to generate key: %s\nReturn code: %s", key_type, ret)
        yield keys

    finally:
        destroy_objects(source_session, keys)


@contextmanager
def create_data_object(session, data_type, num_obj=1):
    template = get_session_template(data_type)
    data_objects = []
    try:
        for _ in range(num_obj):
            h_obj = c_create_object_ex(session, template)
            data_objects.append(h_obj)
        yield data_objects
    finally:
        destroy_objects(session, data_objects)


OBJ_FUNC_MAP = {
    SYM: (gen_sym_keys, SYM_KEYS),
    ASYM: (gen_asym_keys, ASYM_KEYS),
    DATA: (create_data_object, [DATA_TEMPLATE]),
    CERT_DATA: (create_data_object, [CERTIFICATE_TEMPLATE]),
}


def destroy_objects(session, obj_list):
    """common function to destroy objects"""
    for obj in obj_list:
        if obj is not None:
            c_destroy_object(session, obj)


@pytest.fixture(scope="class")
def migration_flags():
    """The value of the migration flag"""
    yield CKF_CPV4_CONTINUE_ON_ERR


def get_migration_data(objects_to_clone, object_type=CK_CRYPTOKI_ELEMENT):
    """Prepares the migration data"""
    mig_data_list = []
    for obj in objects_to_clone:
        mig_data_list.append(MIGRATION_DATA(object_type=object_type, source_handle=obj))

    return mig_data_list


@pytest.fixture(scope="function", params=[CERT_DATA, DATA, SYM, ASYM])
def one_object(request, source_session):
    """generates one object (pair of objects)"""
    func, param = OBJ_FUNC_MAP[request.param]
    with func(source_session, param[0]) as obj:
        yield get_migration_data(obj)


@pytest.fixture(scope="function")
def invalid_object_handle():
    """invalid object handle"""
    yield [MIGRATION_DATA(object_type=CK_CRYPTOKI_ELEMENT, source_handle=11111)]


@pytest.fixture(scope="function", params=INVALID_OBJECTS_TYPES)
def invalid_object_type(request, source_session):
    """Create invalid object types MIGRATION_DATA"""
    with create_data_object(source_session, DATA_TEMPLATE) as data_obj:
        yield [MIGRATION_DATA(object_type=request.param, source_handle=data_obj[0])]


@pytest.fixture(scope="function")
def hundred_objects(source_session):
    """generates 100 token objects"""
    with gen_asym_keys(source_session, ASYM_KEYS[0], 30) as asym_keys, gen_sym_keys(
        source_session, random.choice(SYM_KEYS), 40
    ) as sym_keys:
        yield get_migration_data(asym_keys + sym_keys)


@pytest.fixture(scope="function")
def mix_objects(source_session):
    """generates a mix of sym/asym keys and data and certificate objects"""
    with gen_asym_keys(source_session, ASYM_KEYS[0], 5) as asym_keys, gen_sym_keys(
        source_session, random.choice(SYM_KEYS), 20
    ) as sym_keys, create_data_object(
        source_session, DATA_TEMPLATE, 20
    ) as data_obj, create_data_object(
        source_session, CERTIFICATE_TEMPLATE, 20
    ) as cert_obj:
        yield get_migration_data(asym_keys + sym_keys + data_obj + cert_obj)


def verify_migrated_objects(
    source_session, target_session, source_objs, migrated_objs, expected_retcode=[CKR_OK]
):
    """verifies CA_MigrateKeys result"""

    assert len(source_objs) == len(migrated_objs)

    counter = -1

    for rv, obj_h in migrated_objs:

        counter += 1
        assert rv == expected_retcode[counter]

        if expected_retcode[counter] == CKR_OK:
            src_uid = c_get_attribute_value_ex(
                source_session, source_objs[counter].source_handle, {CKA_OUID: None}
            )[CKA_OUID]

            target_uid = c_get_attribute_value_ex(target_session, obj_h, {CKA_OUID: None})[CKA_OUID]
            assert target_uid == src_uid


def verify_ret(ret, expected_ret):
    """
    Assert that ret is as expected
    :param ret: the actual return value
    :param expected_ret: the expected return value
    """
    assert ret == expected_ret, (
        "Function should return: "
        + ret_vals_dictionary[expected_ret]
        + ".\nInstead returned: "
        + ret_vals_dictionary[ret]
    )


@pytest.fixture(scope="function", autouse=True)
def clean_target_partition(target_session):
    """finds objects in target partition and cleans them"""
    yield
    objs = c_find_objects_ex(target_session, {CKA_TOKEN: True}, 100)
    destroy_objects(target_session, objs)


class TestMigrateKeys(object):
    """
    Testcases for migrating keys.
    """

    def test_migrate_one_obj(self, source_session, target_session, migration_flags, one_object):
        """
        Test migrating keys
        """
        ret, mig_data = ca_migrate_keys(
            source_session, target_session, migration_flags, len(one_object), one_object
        )
        assert ret == CKR_OK
        verify_migrated_objects(
            source_session, target_session, one_object, mig_data, [CKR_OK] * len(one_object)
        )

    def test_migrate_invalid_obj_handle(
        self, source_session, target_session, migration_flags, invalid_object_handle
    ):
        """
        Test migrating keys
        """
        ret, mig_data = ca_migrate_keys(
            source_session,
            target_session,
            migration_flags,
            len(invalid_object_handle),
            invalid_object_handle,
        )
        assert ret == CKR_OK
        verify_migrated_objects(
            source_session,
            target_session,
            invalid_object_handle,
            mig_data,
            [CKR_OBJECT_HANDLE_INVALID],
        )

    def test_migrate_invalid_obj_type(
        self, source_session, target_session, migration_flags, invalid_object_type
    ):
        """
        Test migrating keys
        """
        ret, mig_data = ca_migrate_keys(
            source_session,
            target_session,
            migration_flags,
            len(invalid_object_type),
            invalid_object_type,
        )

        assert ret == CKR_OK
        verify_migrated_objects(
            source_session, target_session, invalid_object_type, mig_data, [CKR_OBJECT_TYPE_INVALID]
        )

    def test_migrate_hundred_obj(
        self, source_session, target_session, migration_flags, hundred_objects
    ):
        """
        Test migrating keys
        """
        ret, mig_data = ca_migrate_keys(
            source_session, target_session, migration_flags, len(hundred_objects), hundred_objects
        )
        assert ret == CKR_OK
        verify_migrated_objects(
            source_session,
            target_session,
            hundred_objects,
            mig_data,
            [CKR_OK] * len(hundred_objects),
        )

    def test_migrate_mix_obj(self, source_session, target_session, migration_flags, mix_objects):
        """
        Test migrating keys
        """
        ret, mig_data = ca_migrate_keys(
            source_session, target_session, migration_flags, len(mix_objects), mix_objects
        )
        assert ret == CKR_OK
        verify_migrated_objects(
            source_session, target_session, mix_objects, mig_data, [CKR_OK] * len(mix_objects)
        )


class TestHello(object):
    def test_start_negotiate(self, target_session):
        """Tests ca_migration_start_session_negotiation"""
        ret, data = ca_migration_start_session_negotiation(target_session)
        verify_ret(ret, CKR_OK)

        output_data = data["output"]
        output_step = data["step"]
        output_len = len(output_data)

        assert output_step == 2
        assert output_data != None
        if output_data:
            assert output_len == len(output_data)

    def test_cont_negotiation(self, source_session, target_session):
        """
        tests ca_migration_continue_session_negotiation,
        for which is needs the output of ca_migration_start_session_negotiation
        """
        ret, data = ca_migration_start_session_negotiation(target_session)
        verify_ret(ret, CKR_OK)

        output = data["output"]
        step = data["step"]
        output_len = len(output)

        ret, neg_data = ca_migration_continue_session_negotiation(source_session, step, output)
        verify_ret(ret, CKR_OK)

        output_step = neg_data["step"]
        output_data = neg_data["output"]
        status = neg_data["status"]
        session_ouid = neg_data["session_ouid"]

        ret, neg_data = ca_migration_continue_session_negotiation(
            target_session, output_step, output_data, session_ouid
        )

        # Uncomment after fix in library from luna
        # verify_ret(ret, CKR_OK)

        # output_step, output_data_len, output_data, status, session_ouid_len, session_ouid = neg_data

    def test_close_session(self, target_session):
        """Tests ca_migration_close_session"""
        ret, data = ca_migration_start_session_negotiation(target_session)
        verify_ret(ret, CKR_OK)

        output = data["output"]
        output_step = data["step"]
        output_len = len(output)

        ret, neg_data = ca_migration_continue_session_negotiation(
            target_session, output_step, output
        )
        verify_ret(ret, CKR_OK)

        session_ouid = neg_data["session_ouid"]

        ret = ca_migration_close_session(target_session, session_ouid)
        verify_ret(ret, CKR_OK)

    def test_extract_insert_one_object(self, source_session, target_session, one_object):

        # Establish secure tunnel
        ret, data = ca_migration_start_session_negotiation(target_session)
        verify_ret(ret, CKR_OK)

        output = data["output"]
        output_step = data["step"]
        output_len = len(output)

        ret, neg_data = ca_migration_continue_session_negotiation(
            source_session, output_step, output
        )
        verify_ret(ret, CKR_OK)

        output_step = neg_data["step"]
        output_data = neg_data["output"]
        status = neg_data["status"]
        session_ouid = neg_data["session_ouid"]

        ret, neg_data = ca_migration_continue_session_negotiation(
            target_session, output_step, output_data
        )

        # Uncomment after fix in library from luna
        # verify_ret(ret, CKR_OK)

        # Extract objects blob from source
        obj_h = [obj.source_handle for obj in one_object]
        obj_t = [obj.object_type for obj in one_object]

        extract_mech = generate_cpv4_extract_mech_params(
            obj_handles=obj_h, obj_type=obj_t, input_param=output_data, session_ouid=session_ouid
        )

        ret = ca_extract(source_session, extract_mech)
        verify_ret(ret, CKR_OK)

        extractedBlobs, extractedBlobsLen = verify_extracted_objects(
            extract_mech.pParameter, [CKR_OK] * len(one_object)
        )

        # Insert object blob to target
        total_objects = len(one_object)
        insert_mech = generate_cpv4_insert_mech(
            input_param=output_data,
            session_ouid=session_ouid,
            number_of_objects=total_objects,
            obj_type=obj_t,
            storage_type=[1] * total_objects,
            key_blob_len=extractedBlobsLen,
            key_blob=extractedBlobs,
        )

        ret = ca_insert(target_session, insert_mech)
        verify_ret(ret, CKR_OK)

        cpv4_params = cast(insert_mech.pParameter, POINTER(CK_CPV4_INSERT_PARAMS)).contents

        numberOfObjs = cpv4_params.numberOfObjects
        results = cpv4_params.result
        objHandles = cpv4_params.objectHandle

        mig_data = []
        for i in range(numberOfObjs):
            mig_data.append((results[i], objHandles[i]))

        verify_migrated_objects(
            source_session, target_session, one_object, mig_data, [CKR_OK] * numberOfObjs
        )

    def test_extract_insert_mix_objects(self, source_session, target_session, mix_objects):

        # Establish secure tunnel
        ret, data = ca_migration_start_session_negotiation(target_session)
        verify_ret(ret, CKR_OK)

        output = data["output"]
        output_step = data["step"]
        output_len = len(output)

        ret, neg_data = ca_migration_continue_session_negotiation(
            source_session, output_step, output
        )
        verify_ret(ret, CKR_OK)

        output_step = neg_data["step"]
        output_data = neg_data["output"]
        status = neg_data["status"]
        session_ouid = neg_data["session_ouid"]

        ret, neg_data = ca_migration_continue_session_negotiation(
            target_session, output_step, output_data
        )

        # Uncomment after fix in library from luna
        # verify_ret(ret, CKR_OK)

        # Extract objects blob from source
        obj_h = [obj.source_handle for obj in mix_objects]
        obj_t = [obj.object_type for obj in mix_objects]

        extract_mech = generate_cpv4_extract_mech_params(
            obj_handles=obj_h, obj_type=obj_t, input_param=output_data, session_ouid=session_ouid
        )

        ret = ca_extract(source_session, extract_mech)
        verify_ret(ret, CKR_OK)

        extractedBlobs, extractedBlobsLen = verify_extracted_objects(
            extract_mech.pParameter, [CKR_OK] * len(obj_h)
        )

        # Insert object blob to target
        total_objects = len(obj_h)
        insert_mech = generate_cpv4_insert_mech(
            input_param=output_data,
            session_ouid=session_ouid,
            number_of_objects=total_objects,
            obj_type=obj_t,
            storage_type=[1] * total_objects,
            key_blob_len=extractedBlobsLen,
            key_blob=extractedBlobs,
        )

        ret = ca_insert(target_session, insert_mech)
        verify_ret(ret, CKR_OK)

        cpv4_params = cast(insert_mech.pParameter, POINTER(CK_CPV4_INSERT_PARAMS)).contents

        numberOfObjs = cpv4_params.numberOfObjects
        results = cpv4_params.result
        objHandles = cpv4_params.objectHandle

        mig_data = []
        for i in range(numberOfObjs):
            mig_data.append((results[i], objHandles[i]))

        verify_migrated_objects(
            source_session, target_session, mix_objects, mig_data, [CKR_OK] * len(mix_objects)
        )
