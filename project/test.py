import logging
from acme_client import ACME_Client

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('ACME_Client')

client = ACME_Client(logger, 'https://localhost:14000/dir')

client.get_new_account()