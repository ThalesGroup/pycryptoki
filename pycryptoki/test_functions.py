from ctypes import byref
from functools import wraps
import inspect
import logging

from defines import CKR_OK
from pycryptoki.attributes import Attributes
from pycryptoki.cryptoki import CK_OBJECT_HANDLE, CK_ULONG, C_GetObjectSize
from pycryptoki.defines import CKR_OBJECT_HANDLE_INVALID
from return_values import ret_vals_dictionary

logger = logging.getLogger(__name__)


def assert_test_return_value(value, expected_value, message, print_on_success=True):
    """Asserts a pass or fail based on whether the value parameter is equal to the expected_value parameter.
    Used to test the results of pkcs11 functions and looks up human readable strings for the various error codes.
    Prints out results in a consistent format.

    :param value: The return value of the pkcs11 function
    :param expected_value: The expected return value to be tested against
    :param message: Message to print on success/failure
    :param print_on_success: Whether or not to print if the test case passes (Default value = True)

    """
    if value in ret_vals_dictionary:
        code = ret_vals_dictionary[value]
    else:
        code = "Unknown Code=" + str(hex(value))

    if expected_value in ret_vals_dictionary:
        exp_code = ret_vals_dictionary[expected_value]
    else:
        exp_code = "Unknown Code=" + str(hex(value))

    assert value == expected_value, "\nERROR: " + message + "\n\tExpected: " + exp_code + "\n\tFound: " + code

    if print_on_success:
        logger.info(exp_code + ": " + message)


def assert_test_case(result, message, print_on_success=False):
    """Simple wrapper around assert that allows for a consistent way to report successes/failures

    :param result: A boolean representing the result of the test
    :param message: The message to print on test failure
    :param print_on_success:  (Default value = False)

    """
    assert result, "\nERROR: " + message
    if print_on_success:
        logger.info("PASSED: " + message)


class LunaException(Exception):
    """A class representing an exception in luna, it's in place because
    it has some nice functionailty to print out the contents of the error


    """

    def __init__(self, error_code, function_name, arguments):
        """
        @param error_code: The error code of the error
        @param function_name: The name of the function
        @param arguments: The arguments passed into the function
        """
        self.error_code = error_code
        self.function_name = function_name
        self.arguments = arguments

        if self.error_code in ret_vals_dictionary:
            self.error_string = ret_vals_dictionary[self.error_code]
        else:
            self.error_string = "Unknown Code=" + str(hex(self.error_code))

    def __str__(self):
        return "\n\tFunction: " + str(self.function_name) + "\n\tError: " + str(self.error_string) \
               + "\n\tError Code: " + str(hex(self.error_code)) + "\n\tArguments: " + str(self.arguments)


class LunaReturn:
    """ """

    def __init__(self, return_code, return_data):
        self.return_code = return_code
        self.return_data = return_data


def verify_object_attributes(h_session, h_object, expected_template):
    """Verifies that an object generated has the correct attributes on the board.
    The expected attributes are passed in alongside the handle of the object.

    :param h_session: Current session
    :param h_object: Handle of the object to verify the attributes against
    :param expected_template: The expected template to compare against

    """

    # VERIFY OBJECT EXISTS
    h_object = CK_OBJECT_HANDLE(h_object)
    us_size = CK_ULONG()
    ret = C_GetObjectSize(h_session, h_object, byref(us_size))
    assert_test_case(ret == CKR_OK, "Object " + str(h_object) + " exists")
    assert_test_case(us_size.value > 0, "Object " + str(h_object.value) + " size is greater than zero.")

    # VERIFY ATTRIBUTES are the same as the ones passed in
    attr = Attributes()
    attr.retrieve_key_attributes(h_session, h_object.value)
    expected_attributes = Attributes(expected_template)
    assert_test_case(attr == expected_attributes,
                     "Object " + str(h_object.value) + " attributes match expected attributes")


def verify_object_exists(h_session, h_object, should_exist=True):
    """Queries the HSM to determine if an object exists. Asserts whether or not
    it exists.

    :param h_session: The current session
    :param h_object: The object to verify if it exists
    :param should_exist: Whether or not the parameter should exist (Default value = True)

    """
    # VERIFY OBJECT EXISTS
    h_object = CK_OBJECT_HANDLE(h_object)
    us_size = CK_ULONG()

    if should_exist:
        expected_ret = CKR_OK
        out = "Verifying object " + str(h_object) + " exists."
    else:
        expected_ret = CKR_OBJECT_HANDLE_INVALID
        out = "Verifying object " + str(h_object) + " doesn't exist."

    try:
        ret = C_GetObjectSize(h_session, h_object, byref(us_size))
    except LunaException as e:
        assert_test_case(e.error_code == expected_ret, out)
    else:
        assert_test_case(ret == expected_ret, out)

    if should_exist:
        assert_test_return_value(ret, CKR_OK, "Getting object " + str(h_object.value) + "'s size", True)
        assert_test_case(us_size.value > 0, "Object " + str(h_object.value) + " size is greater than zero.", False)
    else:
        assert_test_return_value(ret, CKR_OBJECT_HANDLE_INVALID, "Getting object " + str(h_object.value) + "'s size",
                                 True)
        assert_test_case(us_size.value <= 0, "Object " + str(h_object.value) + " size is greater than zero.", False)


def check_luna_exception(ret, luna_function, *args):
    """

    :param ret:
    :param luna_function:
    :param *args:

    """
    arg_spec = inspect.getargspec(luna_function).args
    arg_string = "("
    i = 0
    if len(arg_spec) > 0:
        for argument in args:
            arg_string = arg_string + arg_spec[i] + "=" + str(argument)

            if i != (len(args) - 1):
                arg_string += ", "
            i += 1

    arg_string += ")"
    if ret != CKR_OK: raise LunaException(ret, luna_function.__name__, arg_string)


def make_error_handle_function(luna_function):
    """This function is a helper function that creates a new function which checks the
    result code returned from a function in luna. It is called by calling:

    c_generate_key_pair_ex = make_error_handle_function(c_generate_key_pair)

    This code will create a c_generate_key_pair_ex which will call c_generate_key_pair and check the
    first argument. The first argument is the return code of c_generate_key_pair. If the return
    code != CKR_OK then c_generate_key_pair_ex will raise a LunaException. You can call c_generate_key_pair_ex
    as if it is c_generate_key_pair:

    c_generate_key_pair_ex(h_session, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                        CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP)

    The return values of c_generate_pair are (ret, public_key_handle, private_key_handle)

    The return values of c_generate_pair_ex are (public_key_handle, private_key_handle)

    This lets you create two versions of a function. One version is for setup and
    the other version is for testing the result.

    Directly testing the result:
    ret = c_initialize()
    assert ret == CKR_SOME_ERROR_CODE, "This test case will fail if this condition is not met"

    Expecting the call to go through without error. The test case should have an error (not a failure):
    c_initialize_ex()

    This should therefore make for shorter test cases

    :param luna_function:

    """

    @wraps(luna_function)
    def luna_function_exception_handle(*args, **kwargs):
        """

        :param *args:
        :param **kwargs:

        """
        return_tuple = luna_function(*args, **kwargs)
        if isinstance(return_tuple, tuple):
            if len(return_tuple) > 2:
                return_data = return_tuple[1:]
                ret = return_tuple[0]
            elif len(return_tuple) == 2:
                return_data = return_tuple[1]
                ret = return_tuple[0]
            else:
                return_data = return_tuple[0]
                ret = return_tuple[0]
        elif isinstance(return_tuple, long):
            ret = return_tuple
            return_data = return_tuple
        else:
            raise Exception(
                "Functions wrapped by the exception handler should return a tuple or just the long representing Luna's return code.")

        check_luna_exception(ret, luna_function, args)
        return return_data

    return luna_function_exception_handle
