## Pycryptoki
[![Doc Status](https://readthedocs.org/projects/pycryptoki/badge/?version=latest)](http://pycryptoki.readthedocs.io/en/latest/)

Pycryptoki is a python wrapper around the PKCS11 library.



## Installation

pip install git+https://github.com/gemalto/pycryptoki



## Tests

Unittests can be run on any environment using:
```
py.test tests/unittests
```

Functional tests require an HSM to test against, and will actively test the integration
 with the libCryptoki library. This *will* create and destroy objects on the HSM, so don't run
  on a production HSM!

```
py.test tests/functional --slot=<slot_num> [--reset] [--password=<pwd>] [--copassword=<pwd>] [--user=<user>] [--loglevel=<level>]
```
