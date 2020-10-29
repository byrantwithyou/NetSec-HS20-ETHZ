import base64
import crypto
import time
import requests
import binascii

def to_base64(data):
    if isinstance(data, str):
        data = data.encode("utf8")
    data = base64.urlsafe_b64encode(data)
    data = data.decode("utf8").replace("=", "")
    return data

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def get_protected_header(nonce, url, jwk, kid):
    if(kid == None):
        return {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk}
    else:
        return {"alg": "RS256", "nonce": nonce, "url": url, "kid": kid}

def get_header():
    return {"Content-Type": "application/jose+json"}

def acme_server_request(client, url, payload):
    header = get_header()
    protected_header = get_protected_header(client.acme_nonce, 
        url, None, client.acme_key_id)
    data = crypto.get_jws(protected_header, payload, client.account_private_key)
    r = requests.post(url, headers=header, data=data, verify='pebble.minica.pem')
    client.acme_nonce = r.headers['Replay-Nonce']
    return r

def extract_challenges_dict(response, auth_url, challenge_type):
    for c in response['challenges']:
        if (challenge_type == c['type']):
            challenge = c
    challenge['domain'] = response['identifier']['value']
    challenge['auth_url'] = auth_url
    return challenge

def poll_acme_server(client, url, payload, required_status):
    status = "pending"
    while status != required_status:
        r_dict = acme_server_request(client, url, payload).json()
        status = r_dict['status']
        time.sleep(2)
    return r_dict


