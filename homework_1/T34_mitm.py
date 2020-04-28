import hashlib
from binascii import unhexlify
from os import urandom

from Crypto.Cipher import AES

import encryption_func
from homework_1.T33_diffie_hellman import diffie_hellman


def parameter_injection_attack(alice, bob):
    alice_public = alice.public
    bob_public = bob.public

    plain_text_message = b'My secret pass is qwerty007'
    alice_key = unhexlify(hashlib.sha1(str(alice.get_shared_secret(bob_public)).encode('utf-8')).hexdigest())[:16]
    alice_iv = urandom(AES.block_size)
    alice_message = encryption_func.aes_cbc_encrypt(plain_text_message, alice_key, alice_iv) + alice_iv

    bob_key = unhexlify(hashlib.sha1(str(bob.get_shared_secret(alice_public)).encode('utf-8')).hexdigest())[:16]
    alice_iv = alice_message[-AES.block_size:]
    from_alice = encryption_func.aes_cbc_decrypt(alice_message[:-AES.block_size], bob_key, alice_iv)
    bob_iv = urandom(AES.block_size)
    bob_message = encryption_func.aes_cbc_encrypt(from_alice, bob_key, bob_iv) + bob_iv

    # debug
    assert plain_text_message == from_alice
    mitm_hacked_key = unhexlify(hashlib.sha1(str(b'0').encode('utf-8')).hexdigest())[:16]

    # hack Alice message
    mitm_alice_iv = alice_message[-AES.block_size:]
    mitm_hacked_alice_message = encryption_func.aes_cbc_decrypt(alice_message[:-AES.block_size], mitm_hacked_key,
                                                                mitm_alice_iv)

    # hack Bob message
    mitm_bob_iv = bob_message[-AES.block_size:]
    mitm_hacked_bob_message = encryption_func.aes_cbc_decrypt(bob_message[:-AES.block_size], mitm_hacked_key,
                                                              mitm_bob_iv)

    assert plain_text_message == mitm_hacked_alice_message == mitm_hacked_bob_message


def main_34():
    alice = diffie_hellman()
    bob = diffie_hellman()
    parameter_injection_attack(alice, bob)


main_34()
