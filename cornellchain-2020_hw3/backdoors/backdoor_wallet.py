import binascii
import ecdsa
import random
from ecdsa import SigningKey, VerifyingKey

USERS = ["Alice", "Bob", "Charlie", "Dave"]

def sha256_2_string(string_to_hash):
    """ Returns the SHA256^2 hash of a given string input
    in hexadecimal format.

    Args:
        string_to_hash (str): Input string to hash twice

    Returns:
        str: Output of double-SHA256 encoded as hexadecimal string.
    """

    import hashlib
    first_sha = hashlib.sha256(string_to_hash.encode("utf8"))
    second_sha = hashlib.sha256(first_sha.digest())
    return second_sha.hexdigest()

def is_message_signed(message, hex_sig, secret_key_hex):
    # Decode signature to bytes, verify it
    try:
        signature = binascii.unhexlify(hex_sig)
        pk = SigningKey.from_string(binascii.unhexlify(secret_key_hex)).get_verifying_key()
    except binascii.Error:
        print("binascii error; invalid key")
        return False
    try:
        return pk.verify(signature, message.encode("utf-8"))
    except ecdsa.keys.BadSignatureError:
        print("signature error; invalid signature")
        return False

def verify_key(recovered_key_hex, challenge):
    for line in challenge.splitlines():
        line_challenge = line.split("; Signature: ")
        assert(len(line_challenge) == 2)
        message = line_challenge[0]
        signature = line_challenge[1]
        if not is_message_signed(message, signature, recovered_key_hex):
            return False
        print("Verified signature successfully")
    return True

def get_key_from_challenge(challenge):
    signatures, signatures_binary = list(), list()
    for l in challenge.splitlines(): 
        signatures.append(l.split("; Signature: ")[1])

    for sig in signatures:
        signatures_binary.append(bin(int(sig, 16)).zfill(8))

    priv_key = []
    for sig_bin in signatures_binary:
        priv_key.append(sig_bin[-1])
    priv_key = ''.join(priv_key)
    return hex(int(priv_key, 2))[2:]

challenge_text = open("challenge").read().strip()
sk = get_key_from_challenge(challenge_text)
print(verify_key(sk, challenge_text)) # should print True
