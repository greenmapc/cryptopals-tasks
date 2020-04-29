from random import randint

from homework_2.T39_RSA import int_to_bytes, inversion_by_mod, RSA


def random_int_more_1_mod_n(n):
    s = 0
    while True:
        # s - random int > 1 (mod n)
        s = randint(2, n - 1)
        if s % n > 1:
            break
    return s



# Server for sending blob and return text
class RSAServer:
    def __init__(self, rsa):
        self._rsa = rsa
        self._decrypted = set()

    def get_public_key(self):
        return self._rsa.e, self._rsa.n

    def decrypt(self, data):
        # if text already was was submitted
        if data in self._decrypted:
            raise Exception("This cipher text already was decrypted")
        self._decrypted.add(data)
        return self._rsa.decrypt(data)


def main():
    message = b"I'm the greatest JavaScript developer!"
    # as prev tasks rsa has 512 length
    rsa = RSA(512)
    cipher_text = rsa.encrypt(message)

    rsa_server = RSAServer(rsa)

    # n - public modulus
    # e - exponent
    e, n = rsa_server.get_public_key()
    s = random_int_more_1_mod_n(n)

    # forged cipher text
    forged_cipher_text = (pow(s, e, n) * cipher_text) % n

    # decrypt cipher text and convert to int
    new_message = rsa_server.decrypt(forged_cipher_text)
    int_new_message = int.from_bytes(new_message, byteorder='big')

    # recover sending message (text) as int
    recovered_plaintext =  int_to_bytes((int_new_message * inversion_by_mod(s, n)) % n)

    assert recovered_plaintext == message


main()
