'''
Script used by distutils to automatically generate a source code
distribution of this python module (a .tar.gz file containing
all of the source code).

To generate this file run:
python setup.py sdist
'''
from distutils.core import setup
setup(name='pycryptoki',
      description="A python wrapper around the C cryptoki library.",
      author='Michael Hughes',
      author_email='michael.hughes@safenet-inc.com',
      url='http://mysno/Personal/amer_pohalloran/KnowledgeBaseWiki/Pages/pycryptoki.aspx',
      version='1.2',
      packages=['pycryptoki',
                'pycryptoki.setup',
                'pycryptoki.tests',
                'pycryptoki.daemon',
                'pycryptoki.utils'],
      scripts=['pycryptoki/daemon/rpyc_pycryptoki.py']
      )
