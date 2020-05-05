from base64 import b64decode
from decimal import *
from math import ceil, log

from homework_2.T39_RSA import int_to_bytes, RSA


# Class extends RSA, but contains new method with parity check
class OracleOfParity(RSA):

    def is_parity_odd(self, encrypted_int_data):
        # decryp init data and check parity of number
        return pow(encrypted_int_data, self.mod, self.n) % 2


def binary_search(multiplier, rsa_parity_oracle, left, right, encrypt_data):
    left = Decimal(left)
    right = Decimal(right)
    # Так как из-за нечетности decimal мы не можем сравнивать left и right,
    # необходимо заранее определить границу, до которой мы будем делить на 2
    log_2 = int(ceil(log(rsa_parity_oracle.n, 2)))

    # Необходимо установить точность равную логарифму, чтобы работать с целыми числами
    # и избежать проблем при работе с числами с плавающей точкой
    getcontext().prec = log_2

    for i in range(0, log_2):
        encrypt_data = (encrypt_data * multiplier) % rsa_parity_oracle.n
        mid = (left + right) / 2
        # check every bit
        if rsa_parity_oracle.is_parity_odd(encrypt_data):
            left = mid
        else:
            right = mid

    return right


def oracle_of_parity_attack(encrypt_data, rsa_parity_oracle):
    # find multiplier for encryption text
    multiplier = pow(2, rsa_parity_oracle.e, rsa_parity_oracle.n)

    # determine left and right border for "binary search"
    left = 0
    right = rsa_parity_oracle.n

    decrypt_data = int(binary_search(multiplier, rsa_parity_oracle, left, right, encrypt_data))
    return int_to_bytes(decrypt_data)


def main():
    task_data = b64decode(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    )
    oracle_of_parity = OracleOfParity(1024)

    encrypt_task_data = oracle_of_parity.encrypt(task_data)
    oracle_of_parity.decrypt(encrypt_task_data)

    input_text_result = oracle_of_parity_attack(encrypt_task_data, oracle_of_parity)

    assert input_text_result == task_data

# comment
# message is
# "That's why I found you don't play around with the Funky Cold Medina"


main()
