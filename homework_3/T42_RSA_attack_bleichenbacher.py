import hashlib
import re
from binascii import unhexlify

from homework_2.T39_RSA import int_to_bytes, RSA
from homework_2.T40_RSA_broadcast_attack import cube_sqrt

STANDARD_BLOCK = b'\x00\x01\xff+?\x00.{15}(.{20})'
# ASN.1 value for SHA1
asn1_sha1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
garbage_symbol = b'\x00'


def forge_signature(message, key_length):
    encoded_message = unhexlify(hashlib.sha1(message).hexdigest())

    # PKCS1.5 standard block
    block = b'\x00\x01\xff\x00' + asn1_sha1 + encoded_message
    # generate garbage
    block += ((key_length // 8) - len(block)) * garbage_symbol

    # sign process
    # block to int and get cube sqrt
    forged_sig = cube_sqrt(int.from_bytes(block, byteorder='big'))

    # signature to bytes
    return int_to_bytes(forged_sig)


# RSA class likes RSA from homework2 with two new functions: verify and sign
class RSAWithDigitalSignature(RSA):

    def sign(self, message):
        return self.decrypt(int.from_bytes(message, byteorder='big'))

    def verify_signature(self, encrypted_signature, message):
        # decrypt signature
        signature = garbage_symbol + int_to_bytes(self.encrypt(encrypted_signature))

        # check that signature contains standard block
        r = re.compile(STANDARD_BLOCK, re.DOTALL)
        m = r.match(signature)
        if not m:
            return False
        else:
            # compare hashes
            hashed = m.group(1)
            return hashed == unhexlify(hashlib.sha1(message).hexdigest())


def main():
    rsa_key_length = 1024
    message = b'hi mom'

    forged_signature = forge_signature(message, rsa_key_length)
    assert RSAWithDigitalSignature(rsa_key_length).verify_signature(forged_signature, message)


main()
