import os
import json
import util
import crypto
import logging
import requests

class ACME_Client():

    def __init__(self, logger, acme_server_url): 
        self.logger = logger
        self.logger.info("Setting up the ACME Client")

        self.acme_server_url = acme_server_url
        self.get_directory()
        self.get_new_nonce()

        self.private_key = crypto.create_rsa_private_key()
        self.public_key = self.private_key.public_key()
        self.jwk = crypto.get_jwk_from_public_key(self.public_key)

    def get_directory(self):
        self.logger.info("Get directory of endpoint urls")
        r = requests.get(self.acme_server_url, verify=False)
        r = r.json()
        self.logger.debug(r)
        
        self.acme_newNonce_url = r['newNonce']
        self.acme_newAccount_url = r['newAccount']
        self.acme_newOrder_url = r['newOrder']
        self.acme_revokeCert_url = r['revokeCert']
        self.keyChange_url = r['keyChange']

    def get_new_nonce(self):
        self.logger.info("Get new nonce")
        r = requests.head(self.acme_newNonce_url, verify=False)
        self.acme_nonce = r.headers['Replay-Nonce']
        self.logger.debug(r.headers)

    def get_new_account(self):
        self.logger.info("Get a new account")
        url = self.acme_newAccount_url
        header = util.get_header()
        protected_header = util.get_protected_header(self.acme_nonce, 
            self.acme_newAccount_url, self.jwk)
        payload = {"termsOfServiceAgreed": True}

        data = crypto.get_jws(protected_header, payload, self.private_key)
        r = requests.post(url, headers=header, data=data, verify=False)
        self.logger.debug(r.content)
        