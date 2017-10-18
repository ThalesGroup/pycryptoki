Pycryptoki Daemon Package
=========================

Start ``pycryptoki.daemon.rpyc_pycryptoki.py`` on your remote client, then connect to it
using :class:`~pycryptoki.pycryptoki_client.RemotePycryptokiClient`. You can then
use the RemotePycryptokiClient as if it were local::

    pycryptoki = RemotePycryptokiClient('10.2.96.130', port=8001)
    pycryptoki.c_initialize_ex()  # Executed on the daemon!
    session = pycryptoki.c_open_session_ex(0)
    #etc


daemon.rpyc_pycryptoki
---------------

.. automodule:: pycryptoki.daemon.rpyc_pycryptoki
    :members:
    :undoc-members:
    :show-inheritance:

pycryptoki.pycryptoki_client
----------------------------

.. automodule:: pycryptoki.pycryptoki_client
    :members:
    :undoc-members:
    :show-inheritance:
