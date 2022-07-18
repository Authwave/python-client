key = "This can be any string, but a long random string is best." # define private key
message = b"Hello? Testing, testing!" # define message

# new message object with message string and key
from cryptography.fernet import Fernet
from cryptography import utils
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import base64
import os
import typing


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60

# class fernet2(Fernet):
#     @classmethod
#     def generate_key(cls) -> bytes:
#         return base64.urlsafe_b64encode(os.urandom(32)) # 256bit

key = Fernet.generate_key()
fernet = Fernet(key)
token = fernet.encrypt(message)
print(token)

# let's do it again with our custom fernet class
class Fernet2(Fernet) :

    def encrypt_at_time(self, data: bytes, current_time: int) -> bytes:
        # double the iv length to go from 128bit to 256 bit encryption
        #iv = os.urandom(16) # changed 16 -> 32 
        iv = b'\xdc\x95M\xf3\x14\x8bb\xa0-\x06p\x0e\x19\xf5\x84\xb9' 
        # hex: 'dc954df3148b62a02d06700e19f584b9'
        # b'\xdc\x95M\xf3\x14\x8bb\xa0-\x06p\x0e\x19\xf5\x84\xb9'
        return self._encrypt_from_parts(data, current_time, iv)
    
    def _encrypt_from_parts(
        self, data: bytes, current_time: int, iv: bytes
    ) -> bytes:
        utils._check_bytes("data", data)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key),
            modes.CTR(iv),
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x80"
            + current_time.to_bytes(length=8, byteorder="big")
            + iv
            + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256())
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)
        #return ciphertext

    def _decrypt_data(
        self,
        data: bytes,
        timestamp: int,
        time_info: typing.Optional[typing.Tuple[int, int]],
    ) -> bytes:
        if time_info is not None:
            ttl, current_time = time_info
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        self._verify_signature(data)

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(iv)
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded

key = b'Yk4SaA-yRdL-g2g8-jo46D9UkmJmg_zG2doCQ8ZbxAU='
#bytes: bN\x12h\x0f\xb2E\xd2\xfe\x83h<\xfa:8\xe8?T\x92bf\x83\xfc\xc6\xd9\xda\x02C\xc6[\xc4\x05
#hex: '596b345361412d7952644c2d673267382d6a6f34364439556b6d4a6d675f7a4732646f4351385a627841553d'
fernet = Fernet2(key)
token = fernet.encrypt(message)
print(token.hex())
print(fernet.decrypt(token))


# send to page



# # tests
# import requests
# r = requests.get('http://localhost:8080/receiver.php')
# print(r.content)
