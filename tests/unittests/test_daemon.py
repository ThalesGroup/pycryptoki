"""
Testcases for the RPYC Daemon & Client.
"""
import logging
import os
import random

import pytest
from pycryptoki.daemon.rpyc_pycryptoki import (
    PycryptokiService,
    create_server_subprocess,
    server_launch,
)
from pycryptoki.default_templates import get_default_key_template
from pycryptoki.defines import CKM_AES_KEY_GEN
from pycryptoki.pycryptoki_client import RemotePycryptokiClient


@pytest.fixture()
def local_rpyc():
    """
    Spin up a local-only RPYC Pycryptoki daemon in a subprocess.
    """
    logger = logging.getLogger(__name__)
    server_config = {
        "allow_public_attrs": True,
        "allow_all_attrs": True,
        "allow_getattr": True,
        "allow_setattr": True,
        "allow_delattr": True,
    }
    port = random.randint(10000, 65535)
    server = create_server_subprocess(
        server_launch, args=(PycryptokiService, "127.0.0.1", port, server_config), logger=logger,
    )
    assert server.exitcode is None
    assert server.is_alive()
    yield port
    server.terminate()


class TestPycryptokiDaemon(object):
    def test_simple_connect(self, local_rpyc):
        client = RemotePycryptokiClient("127.0.0.1", local_rpyc)
        assert client.test_conn()

    def test_attribute_delivery(self, local_rpyc):
        client = RemotePycryptokiClient("127.0.0.1", local_rpyc)
        client.test_attrs(get_default_key_template(CKM_AES_KEY_GEN))
