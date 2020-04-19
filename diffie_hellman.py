from random import randint


class diffie_hellman:
    default_p = int(
        'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
        'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
        '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
        '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
        '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
        'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
        'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
        'fffffffffffff', 16
    )
    default_g = 2

    def __init__(self, p=default_p, g=default_g):
        self.p = p
        self.g = g
        self.secret = randint(0, p - 1)
        print(self.secret)
        self.public = pow(g, self.secret, p)
        self.shared = None

    def derive_shared_secret(self, B):
        self.shared = pow(B, self.secret, self.p)


import unittest

class diffie_hellman_test(unittest.TestCase):

    def test_getting_key(self):
        default_alice = diffie_hellman()
        default_bob = diffie_hellman()
        default_alice.derive_shared_secret(default_bob.public)
        default_bob.derive_shared_secret(default_alice.public)
        self.assertEqual(default_alice.shared, default_bob.shared)
