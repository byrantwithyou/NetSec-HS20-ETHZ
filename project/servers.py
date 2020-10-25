from flask import Flask, make_response
from multiprocessing import Process
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
from dnslib.dns import RR
import copy

class ChallengeServer(Process):

    def __init__(self, token, key_authorization):
        Process.__init__(self)
        self.token = token
        self.key_authorization = key_authorization

    def run(self):
        self.app = Flask(__name__)

        @self.app.route('/.well-known/acme-challenge/' + self.token)
        def challenge_response():
            response = make_response(self.key_authorization, 200)
            response.headers['Content-Type'] = 'application/octet-stream'
            print("hallovelo connection accepted")
            return response

        self.app.run(host="localhost", port=5002)

class FixedResolver(BaseResolver):
    '''
    The FixedResolver object is a DNS resolver that returns a DNS response with the specified 
    DNS zone and if specified (challenge mode) the passed URL. If no URL is passed, the domain 
    in the DNS response will be the domain of the DNS request
    :param zone: The DNS zone the resolver will return
    :type zone: str, required
    :param url: The URL the resolver will return
    :type url: str, optional
    '''
    def __init__(self, zone, url):
        # Parse RRs
        self.rrs = RR().fromZone(zone)
        self.url = url

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname

        # if self.url is set: challenge mode
        # return dns challenge url
        if self.url is not None:
            qname = self.url

        # Replace labels with request label
        for rr in self.rrs:
            a = copy.copy(rr)
            a.rname = qname
            reply.add_answer(a)
        print(reply)
        return reply