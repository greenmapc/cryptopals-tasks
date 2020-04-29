from homework_2.T39_RSA import RSA, inversion_by_mod, int_to_bytes


def cube_sqrt(n):
    # realization of cube sqrt for binary search
    left = 0
    right = n

    while left < right:
        mid = (left + right) // 2
        if mid ** 3 < n:
            left = mid + 1
        else:
            right = mid

    return left


def main():
    secret_text = b"I'm the greatest JavaScript developer!"

    three_ciphers_texts = []
    result = b''
    for i in range(3):
        # RSA key length for example 512
        rsa = RSA(512)
        three_ciphers_texts.append((rsa.encrypt(secret_text), rsa.n))

        # CRT
    c0, c1, c2 = three_ciphers_texts[0][0], three_ciphers_texts[1][0], three_ciphers_texts[2][0]
    n0, n1, n2 = three_ciphers_texts[0][1], three_ciphers_texts[1][1], three_ciphers_texts[2][1]
    m0, m1, m2 = n1 * n2, n0 * n2, n0 * n1

    first_term = c0 * m0 * inversion_by_mod(m0, n0)
    second_term = c1 * m1 * inversion_by_mod(m1, n1)
    third_term = c2 * m2 * inversion_by_mod(m2, n2)

    c = (first_term + second_term + third_term) % (n0 * n1 * n2)
    result = int_to_bytes(cube_sqrt(c))

    assert result == secret_text


main()
