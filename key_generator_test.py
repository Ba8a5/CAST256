import unittest

from key_generator import key_generator

k = 0x2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604


class TestKeyGenerator(unittest.TestCase):

    def test_KeyRound1(self):
        kr, km = key_generator(k)

        assert kr[0][0] == 0x08
        assert kr[0][1] == 0x12
        assert kr[0][2] == 0x0e
        assert kr[0][3] == 0x17

        assert km[0][0] == 0x420b1cef
        assert km[0][1] == 0x03f07e80
        assert km[0][2] == 0xcd2ab3ee
        assert km[0][3] == 0x15371a16

    def test_KeyRound10(self):
        kr, km = key_generator(k)

        assert kr[9][0] == 0x1b
        assert kr[9][1] == 0x00
        assert kr[9][2] == 0x01
        assert kr[9][3] == 0x01

        assert km[9][0] == 0x2cf3fd07
        assert km[9][1] == 0x75580ec1
        assert km[9][2] == 0x513614b9
        assert km[9][3] == 0x478097ef

