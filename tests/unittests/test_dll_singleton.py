"""
Verify the ChrystokDLLSingleton behavior is correct when creating a from-chrystoki DLL link,
or using the ``from_path`` variation.
"""
import mock

from pycryptoki.cryptoki_helpers import CryptokiDLLSingleton


class TestDllSingleton(object):
    def test_simple_singleton(self):
        with mock.patch("pycryptoki.cryptoki_helpers.CDLL"):
            with mock.patch("pycryptoki.cryptoki_helpers.parse_chrystoki_conf") as chrystoki_conf:
                chrystoki_conf.return_value = "conf_path"
                dll_class = CryptokiDLLSingleton()
                assert dll_class.dll_path == "conf_path"

    def test_from_path_singleton_simple(self):
        with mock.patch("pycryptoki.cryptoki_helpers.CDLL"):
            dll_class = CryptokiDLLSingleton.from_path("testpath")
            assert dll_class.dll_path == "testpath"

    def test_from_path_singleton_multiple_same(self):
        with mock.patch("pycryptoki.cryptoki_helpers.CDLL"):
            dll_class = CryptokiDLLSingleton.from_path("testpath")
            assert dll_class.dll_path == "testpath"
            dll_class2 = CryptokiDLLSingleton.from_path("testpath")
            dll_class3 = CryptokiDLLSingleton.from_path("testpath")

            assert dll_class == dll_class2 == dll_class3

    def test_from_path_singleton_multiple_diff(self):
        with mock.patch("pycryptoki.cryptoki_helpers.CDLL"):
            dll_class = CryptokiDLLSingleton.from_path("testpath")
            assert dll_class.dll_path == "testpath"
            dll_class2 = CryptokiDLLSingleton.from_path("testpath")
            assert dll_class2.dll_path == "testpath"

            dll_class3 = CryptokiDLLSingleton.from_path("testpath3")
            assert dll_class3.dll_path == "testpath3"

            with mock.patch("pycryptoki.cryptoki_helpers.parse_chrystoki_conf") as chrystoki_conf:
                chrystoki_conf.return_value = "conf_path"
                original_dll = CryptokiDLLSingleton()
                assert original_dll.dll_path == "conf_path"

            assert dll_class == dll_class2
            assert dll_class != original_dll
            assert dll_class != dll_class3
