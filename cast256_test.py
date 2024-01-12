import unittest

from cast256 import encrypt_block, decrypt_block

k = 0x2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604


class TestCast256(unittest.TestCase):

    def test_encrypt_bloc(self):
        message = 0x00000000000000000000000000000000
        cipher = encrypt_block(message, k)
        assert cipher == 0x4f6a2038286897b9c9870136553317fa

    def test_decrypt_bloc(self):
        message = 0x4f6a2038286897b9c9870136553317fa
        cipher = decrypt_block(message, k)
        assert cipher == 0x00000000000000000000000000000000
