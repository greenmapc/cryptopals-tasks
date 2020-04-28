import hashlib
from binascii import unhexlify
from os import urandom

from Crypto.Cipher import AES

import encryption_func
from homework_1.T33_diffie_hellman import diffie_hellman


def mitm():
    p = diffie_hellman.default_p

    for g in [1, p, p - 1]:

        alice = diffie_hellman()
        bob = diffie_hellman()
        bob.get_shared_secret(alice.public)
        alice.get_shared_secret(bob.public)

        sha1 = hashlib.sha1()
        a_msg = 'My password is qwerty1234567'
        a_iv = urandom(AES.block_size)
        a_key = unhexlify(hashlib.sha1(str(alice.shared).encode('utf-8')).hexdigest())[:16]
        a_sends = encryption_func.aes_cbc_encrypt(a_msg, a_key, a_iv), a_iv

        # alice send message
        print(a_sends)

        mitm_a_iv = a_sends[-AES.block_size:]

        # When g is 1, key also 1
        if g == 1:
            mitm_hacked_key = unhexlify(hashlib.sha1(str(b'1').encode('utf-8')).hexdigest())[:16]
            mitm_hacked_message = encryption_func.aes_cbc_decrypt(a_sends[:-AES.block_size], mitm_hacked_key, mitm_a_iv)

        elif g == p:
            mitm_hacked_key = unhexlify(sha1(b'0').encode('utf-8'))[:16]
            mitm_hacked_message = encryption_func.aes_cbc_decrypt(a_sends[:-AES.block_size], mitm_hacked_key, mitm_a_iv)
        else:
            for candidate in [str(1).encode('utf-8'), str(p - 1).encode('utf-8')]:
                mitm_hacked_key = unhexlify(sha1(candidate).encode('utf-8'))[:16]
                mitm_hacked_message = encryption_func.aes_cbc_decrypt(a_sends[:-AES.block_size], mitm_hacked_key, mitm_a_iv, unpad=False)

                if encryption_func.has_pkcs7_padding(mitm_hacked_message):
                    mitm_hacked_message = encryption_func.pkcs7_delete_padding(mitm_hacked_message)
                    break

        assert a_msg == mitm_hacked_message


mitm()
