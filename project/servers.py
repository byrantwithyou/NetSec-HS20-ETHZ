from flask import Flask, make_response, request
from multiprocessing import Process
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
from dnslib.dns import RR
import copy

class ChallengeServer(Process):

    def __init__(self, token, key_authorization, host):
        Process.__init__(self)
        self.token = token
        self.key_authorization = key_authorization
        self.host = host

    def run(self):
        self.app = Flask(__name__)

        @self.app.route('/.well-known/acme-challenge/' + self.token)
        def challenge_response():
            return self.key_authorization

        self.app.run(host=self.host, port=5002)

class DnsResolver(BaseResolver):
    def __init__(self, zone):
        self.zone = zone

    def resolve(self, request, handler):
        reply = request.reply()
        reply.add_answer(*RR.fromZone(self.zone))
        return reply

class CertificateServer(Process):

    def __init__(self, cert, host):
        Process.__init__(self)
        self.certificate = cert
        self.host = host

    def run(self):
        self.app = Flask(__name__)

        @self.app.route('/')
        def return_certificate():
            return self.certificate

        self.app.run(host=self.host, port=5001)

class ShutdownServer:
    # This Server should be blocking and thus
    # does not inherit from multiprocessing Process!
    def run(self, host):
        self.app = Flask(__name__)

        @self.app.route('/shutdown')
        def shutdown_server():
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            return "Shutting down the Server"

        self.app.run(host=host, port=5003)