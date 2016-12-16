"""
Script used by distutils to automatically generate a source code
distribution of this python module (a .tar.gz file containing
all of the source code).

To generate this file run:
python setup.py sdist
"""
from setuptools import setup

setup(name='pycryptoki',
      description="A python wrapper around the C cryptoki library.",
      author='Ashley Straw',
      url='https://github.com/gemalto/pycryptoki',
      version='2.0.1',
      packages=['pycryptoki',
                'pycryptoki.daemon'],
      scripts=['pycryptoki/daemon/rpyc_pycryptoki.py'],
      tests_require=['pytest', 'hypothesis', 'mock', 'pytz'],
      install_requires=['future', 'rpyc', 'six']
      )
