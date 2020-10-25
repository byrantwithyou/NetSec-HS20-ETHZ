import logging
import crypto
import requests
import util
import time
from servers import ChallengeServer, FixedResolver
from acme_client import ACME_Client

from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger, DNSRecord
from dnslib.dns import RR

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('ACME_Client')

client = ACME_Client(logger, 'https://localhost:14000/dir')

client.create_account()
client.submit_order(["www.example.ch"])

# client.get_challenges('http-01')
# client.http_01_challenge()

client.get_challenges('dns-01')
client.dns_01_challenge()
