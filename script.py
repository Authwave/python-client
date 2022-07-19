import pysodium as s # for sodium
import os
import base64

message = b'This message will be sent from sender to receiver via PyNaCl!'

## Create details for sender
# create keypair
senderKeyPair = s.crypto_box_keypair()
# save public and secret key
senderPublicKey = senderKeyPair[0]
senderSecretKey = senderKeyPair[1]

## Create details for receiver
# create key pair
receiverKeyPair = s.crypto_box_keypair()
# save public and secret key
receiverPublicKey = receiverKeyPair[0]
receiverSecretKey = receiverKeyPair[1]

# create cryptographically secure random bytes for initialisation vector
iv = os.urandom(s.crypto_box_NONCEBYTES)

# This makes subequent encryption faster, which is really good
# for this type of application where a client and server would
# communicate for a while before closing a session
lockingKeyPair = s.crypto_box_beforenm(
    receiverPublicKey,
    senderSecretKey
)

# encrypt with lockingkeypair
encryptedBytes = s.crypto_box_afternm(message, iv, lockingKeyPair)
#encryptedBytes = s.crypto_box(message, iv, receiverPublicKey, senderSecretKey)
#and encode to base64 for easy transmission
cipher = base64.urlsafe_b64encode(encryptedBytes)

print(cipher)
#### can transmit data over net here safely

# Here we create the unlocking key pair. It's the same as what
# we did earlier, but this can be used by the receiever, not
# the sender.
unlockingKeyPair = s.crypto_box_beforenm(
    senderPublicKey,
    receiverSecretKey
)

decryptdecode = base64.urlsafe_b64decode(cipher)

#decrypted = s.crypto_box_open(decryptdecode, iv, senderPublicKey, receiverSecretKey)
decrypted = s.crypto_box_open_afternm(decryptdecode, iv, unlockingKeyPair)

print(decrypted.hex())
print(decrypted)

with open("output.txt", "a") as o:
    o.write(decrypted.decode())
