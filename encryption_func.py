from Crypto.Cipher import AES


def pkcs7_padding(message, block_size):
    if len(message) == block_size:
        return message
    message = message.encode('utf-8')
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)


def xor(binary_data_1, binary_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])


def aes_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_padding(data, AES.block_size))


def aes_cbc_encrypt(data, key, iv):
    cipher_text = b''
    prev = iv

    for i in range(0, len(data), AES.block_size):
        curr_plaintext_block = pkcs7_padding(data[i:i + AES.block_size], AES.block_size)
        if isinstance(curr_plaintext_block, str):
            curr_plaintext_block = curr_plaintext_block.encode('utf-8')
        block_cipher_input = xor(curr_plaintext_block, prev)
        encrypted_block = aes_ecb_encrypt(block_cipher_input, key)
        cipher_text += encrypted_block
        prev = encrypted_block

    return cipher_text


def has_pkcs7_padding(binary_data):
    padding = binary_data[-binary_data[-1]:]
    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def pkcs7_delete_padding(data):
    if len(data) == 0:
        raise Exception("empty content")

    if not has_pkcs7_padding(data):
        return data

    padding_len = data[len(data) - 1]
    return data[:-padding_len]


def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_delete_padding(cipher.decrypt(data))


def aes_cbc_decrypt(data, key, iv, unpad=True):
    plaintext = b''
    prev = iv
    for i in range(0, len(data), AES.block_size):
        curr_ciphertext_block = data[i:i + AES.block_size]
        decrypted_block = aes_ecb_decrypt(curr_ciphertext_block, key)
        plaintext += xor(prev, decrypted_block)
        prev = curr_ciphertext_block
    return pkcs7_delete_padding(plaintext) if unpad else plaintext
