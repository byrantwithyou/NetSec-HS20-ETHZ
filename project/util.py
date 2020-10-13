import base64
import binascii

def to_base64(data):
    if isinstance(data, str):
        data = data.encode("utf8")
    data = base64.urlsafe_b64encode(data)
    data = data.decode("utf8").replace("=", "")
    return data

def get_protected_header(nonce, url, jwk):
    return {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk}

def get_header():
    return {"Content-Type": "application/jose+json", "User-Agent": "acme-client"}

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def stringify_dict(payload):
    '''
    Convert keys and values of dict to string
    :param payload: A dict to convert
    :type payload: dict
    :returns: dict with string keys and values
    :rtype: dict
    '''
    if isinstance(payload, str):
        return payload
    elif isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(key, bytes):
                key = key.decode("utf-8")
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            payload[key] = value
        return payload
    else:
        raise ValueError(
            "Unsupported payload type {0} for _stringify_dict()".format(type(payload))
        )

