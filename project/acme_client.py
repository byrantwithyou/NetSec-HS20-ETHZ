import os
import util
import crypto
import hashlib
import logging
import requests

from servers import ChallengeServer, DnsResolver
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger, DNSRecord
from dnslib.dns import RR

class ACME_Client():
    """
    A class implementing an ACME client, that can communicate with an ACME
    server according to the protocol.
    """

    def __init__(self, logger, acme_server_url, record_addr, domains): 
        self.logger = logger
        self.logger.info("Setting up the ACME Client")

        self.record_addr = record_addr
        self.domains = domains
        self.acme_server_url = acme_server_url
        self.get_directory()
        self.get_new_nonce()

        self.account_private_key = crypto.create_rsa_private_key()
        self.certificate_private_key = crypto.create_rsa_private_key()
        crypto.write_private_key(self.certificate_private_key, 'pk.pem')
        self.account_public_key = self.account_private_key.public_key()
        self.jwk = crypto.get_jwk_from_public_key(self.account_public_key)

    def get_directory(self):
        self.logger.info("Get directory of endpoint urls")
        r = requests.get(self.acme_server_url, verify='pebble.minica.pem')
        r = r.json()
        self.logger.debug(r)
        
        self.acme_newNonce_url = r['newNonce']
        self.acme_newAccount_url = r['newAccount']
        self.acme_newOrder_url = r['newOrder']
        self.acme_revokeCert_url = r['revokeCert']
        self.keyChange_url = r['keyChange']

    def get_new_nonce(self):
        self.logger.info("Get new nonce")
        r = requests.head(self.acme_newNonce_url, verify='pebble.minica.pem')
        self.acme_nonce = r.headers['Replay-Nonce']
        self.logger.debug(r.headers)

    def create_account(self):
        self.logger.info("Get a new account")
        url = self.acme_newAccount_url
        header = util.get_header()
        protected_header = util.get_protected_header(self.acme_nonce, 
            url, self.jwk, None)
        payload = {"termsOfServiceAgreed": True}
        data = crypto.get_jws(protected_header, payload, self.account_private_key)
        
        r = requests.post(url, headers=header, data=data, verify='pebble.minica.pem')
        self.acme_nonce = r.headers['Replay-Nonce']
        self.acme_key_id = r.headers['Location']
        self.logger.debug(r.json())

    def submit_order(self, order_domains):
        self.logger.info("Submitting a new order")
        url = self.acme_newOrder_url
        identifiers = []
        for domain in order_domains:
            identifiers.append({"type": "dns", "value": domain})
        payload = {"identifiers": identifiers}
        r = util.acme_server_request(self, url, payload)
        r_dict = r.json()
        self.acme_authorization_urls = r_dict['authorizations']
        self.acme_finalize_url = r_dict['finalize']
        self.acme_order_url = r.headers['Location']
        self.logger.debug(r_dict)
        self.logger.debug(r.headers)

    def get_challenges(self, challenge_type='http-01'):
        self.logger.info("Fetching Challenges")
        self.acme_challenges = []
        for url in self.acme_authorization_urls:
            r_dict = util.acme_server_request(self, url, "").json()
            cur_challenge = util.extract_challenges_dict(r_dict, 
                url, challenge_type)
            self.acme_challenges.append(cur_challenge)
        self.logger.debug(self.acme_challenges)

    def http_01_challenge(self):
        self.logger.info("Performing http-01 challenge")
        for challenge in self.acme_challenges:
            token = challenge["token"]
            chall_url = challenge["url"]
            key_auth = crypto.get_key_authorization(token, self.jwk)

            print(self.record_addr)

            zone = ". 60 IN A " + self.record_addr
            resolver = DnsResolver(zone)
            dns_server = DNSServer(resolver, address=self.record_addr, port=10053)
            dns_server.start_thread()

            challenge_server = ChallengeServer(token, key_auth, self.record_addr)
            challenge_server.start()

            r_dict = util.acme_server_request(self, chall_url, {}).json()
            self.logger.debug(r_dict)

            _dict = util.poll_acme_server(self, challenge['auth_url'], "", "valid")
            self.logger.debug(r_dict)

            challenge_server.terminate()
            challenge_server.join()
            dns_server.stop()
        return
    
    def dns_01_challenge(self):
        self.logger.info("Performing dns-01 challenge")
        for challenge in self.acme_challenges:
            token = challenge["token"]
            chall_url = challenge["url"]
            key_auth = crypto.get_key_authorization(token, self.jwk)
            hashed_key_auth = hashlib.sha256(key_auth.encode('utf-8')).digest()
            hashed_key_auth = util.to_base64(hashed_key_auth)

            zone = ". 300 IN TXT " + hashed_key_auth
            resolver = DnsResolver(zone)
            dns_server = DNSServer(resolver, address=self.record_addr, port=10053)
            dns_server.start_thread()

            r_dict = util.acme_server_request(self, chall_url, {}).json()
            self.logger.debug(r_dict)

            r_dict = util.poll_acme_server(self, challenge['auth_url'], "", "valid")
            self.logger.debug(r_dict)

            dns_server.stop()
        return
    
    def finalize_order(self):
        self.logger.info("Finalizing Order!")
        request = crypto.get_csr(self.domains, self.certificate_private_key)
        payload = {'csr': request}
        r = util.acme_server_request(self, self.acme_finalize_url, payload)
        r_dict = r.json()
        self.logger.debug(r_dict)

        r_dict = util.poll_acme_server(self, self.acme_order_url, "", 'valid')
        self.acme_certificate_url = r_dict['certificate']
        self.logger.debug(r_dict)

    def download_certificate(self):
        self.logger.info("Downloading certificate to cert.pem")
        r = util.acme_server_request(self, self.acme_certificate_url, "") 
        self.acme_certificate = r.content.decode("utf-8")
        crypto.write_certificate(r.content, 'cert.pem')
        self.logger.debug(self.acme_certificate)


