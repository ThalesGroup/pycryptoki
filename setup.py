"""
Script used by distutils to automatically generate a source code
distribution of this python module (a .tar.gz file containing
all of the source code).

To generate this file run:
python setup.py sdist
"""
from setuptools import setup

setup(
    name="pycryptoki",
    description="A python wrapper around the C cryptoki library.",
    author="Ashley Straw",
    url="https://github.com/gemalto/pycryptoki",
    version="2.5.1",
    packages=[
        "pycryptoki",
        "pycryptoki.cryptoki",
        "pycryptoki.daemon",
        "pycryptoki.mechanism",
        "pycryptoki.ca_extensions",
    ],
    scripts=["pycryptoki/daemon/rpyc_pycryptoki.py"],
    tests_require=["pytest==3.10.1", "hypothesis==4.6.1", "mock", "pytz"],
    install_requires=[
        "future",
        "rpyc==3.4.4;python_version<='2.7'",
        "rpyc==4.0.2;python_version>'3'",
        "six",
    ],
)
