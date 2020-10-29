import logging
import util
from servers import ChallengeServer
from servers import CertificateServer, ShutdownServer
from acme_client import ACME_Client
from argparse import ArgumentParser

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('ACME_Client')

# Parse arguments from commandline
parser = ArgumentParser()
parser.add_argument('--chall')
parser.add_argument('--dir')
parser.add_argument('--record')
parser.add_argument('--domain', nargs='*')
parser.add_argument('--revoke', action='store_true')
arguments = parser.parse_args()

client = ACME_Client(logger, arguments.dir, 
    arguments.record, arguments.domain)

client.create_account()
client.submit_order(arguments.domain)

if(arguments.chall == 'http01'):
    client.get_challenges('http-01')
    client.http_01_challenge()
else:
    client.get_challenges('dns-01')
    client.dns_01_challenge()

client.finalize_order()
client.download_certificate()

if(arguments.revoke):
    client.revoke_certificate()

# start certificate server
certificate_server = CertificateServer(client.acme_certificate_str, arguments.record)
certificate_server.start()


# start the shutdown server 
shutdown_server = ShutdownServer()
shutdown_server.run(arguments.record)

# stop certificate server when shutdown was requested
certificate_server.terminate()
certificate_server.join()
