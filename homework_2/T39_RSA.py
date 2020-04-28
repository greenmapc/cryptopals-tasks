from Crypto.Util.number import getPrime


def int_to_bytes(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big')


def greatest_common_divisor(a, b):
    while a != 0 and b != 0:
        if a > b:
            a = a % b
        else:
            b = b % a
    return a + b


def inversion_by_mod(a, n):
    res = 0
    r = n
    candidate = 1
    next_r = a

    # Алгоритм Евклида
    while next_r != 0:
        quotient = r // next_r
        res, candidate = candidate, res - quotient * candidate
        r, next_r = next_r, r - quotient * next_r

    return res + n


class RSA:
    def __init__(self, key_length):
        self.e = 3
        euler = 0

        while greatest_common_divisor(self.e, euler) != 1:
            # using python library for getting prime numbers
            p, q = getPrime(key_length // 2), getPrime(key_length // 2)
            # calculate for find lowest common multiple
            euler = (p - 1) // greatest_common_divisor((p - 1), (q - 1)) * (q - 1)
            self.n = p * q

        self.mod = inversion_by_mod(self.e, euler)

    def encrypt(self, binary_data):
        # bytes to int and RSA encrypts
        int_data = int.from_bytes(binary_data, byteorder='big')
        return pow(int_data, self.e, self.n)

    def decrypt(self, encrypted_int_data):
        # RSA encrypts  and int to bytes
        int_data = pow(encrypted_int_data, self.mod, self.n)
        return int_to_bytes(int_data)


def main():
    # Check mod_inversion
    assert inversion_by_mod(17, 3120) == 2753

    # Check RSA
    # RSA length for example 512
    rsa = RSA(512)
    secret_text = b"Hey! Can I say my password?"
    assert rsa.decrypt(rsa.encrypt(secret_text)) == secret_text


main()
