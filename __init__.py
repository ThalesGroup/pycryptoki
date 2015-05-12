import logging
import sys

logging.basicConfig(stream=sys.stdout,
                    level=logging.DEBUG,
                    format='%(asctime)s:%(name)s:%(levelname)s: %(message)s')
logging.getLogger(__name__).addHandler(logging.NullHandler())
