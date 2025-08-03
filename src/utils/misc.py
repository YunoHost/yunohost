import os
import binascii

def random_ascii(length: int = 40) -> str:
    """Return a random ascii string"""
    return binascii.hexlify(os.urandom(length)).decode("ascii")[:length]
