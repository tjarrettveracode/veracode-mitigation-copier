import os
import time
try:
    # py3
    import configparser
except ImportError:
    # py2
    import ConfigParser as configparser
from hashlib import sha256
import hmac
import codecs
import binascii


class VeracodeHMACError(Exception):
    """Raised when something goes wrong with generating an HMAC header"""
    pass


def _get_creds_from_config_file(auth_file):
    if not os.path.exists(auth_file):
        print("Missing Veracode credentials file, have you set up ~/.veracode/credentials?")
        return

    config = configparser.ConfigParser()
    config.read(auth_file)
    credentials_section_name = os.environ.get("VERACODE_API_PROFILE", "default")
    api_key_id = config.get(credentials_section_name, "VERACODE_API_KEY_ID")
    api_key_secret = config.get(credentials_section_name, "VERACODE_API_KEY_SECRET")
    if api_key_id and api_key_secret:
        return api_key_id, api_key_secret
    else:
        print("Missing credentials in file, have you correctly set up ~/.veracode/credentials?")


def _get_creds():
    auth_file = os.path.join(os.path.expanduser("~"), '.veracode', 'credentials')
    return _get_creds_from_config_file(auth_file)


def _get_timestamp():
    return int(round(time.time() * 1000))


def _get_nonce():
    return binascii.hexlify(os.urandom(16)).decode()


def _create_signature(api_secret, signing_data, timestamp, nonce):
    key_nonce = hmac.new(codecs.decode(api_secret, "hex_codec"), codecs.decode(nonce, "hex_codec"), sha256).digest()
    key_date = hmac.new(key_nonce, str(timestamp).encode(), sha256).digest()
    signature_key = hmac.new(key_date, u"vcode_request_version_1".encode(), sha256).digest()
    return hmac.new(signature_key, signing_data.encode(), sha256).hexdigest()


def generate_veracode_hmac_header(host, url, method):
    api_id, api_secret = _get_creds()
    if not api_id or not api_secret:
        raise VeracodeHMACError

    signing_data = "id={api_id}&host={host}&url={url}&method={method}".format(api_id=api_id.lower(),
                                                                              host=host.lower(),
                                                                              url=url, method=method.upper())
    timestamp = _get_timestamp()
    nonce = _get_nonce()
    signature = _create_signature(api_secret, signing_data, timestamp, nonce)
    return "{auth_scheme} id={id},ts={ts},nonce={nonce},sig={sig}".format(auth_scheme="VERACODE-HMAC-SHA-256", id=api_id,
                                                                          ts=timestamp, nonce=nonce, sig=signature)
