import unittest

from functions_cast256 import *


class TestCast256(unittest.TestCase):

    def test_substitution(self):
        sisi = 942674285
        o1, o2, o3, o4 = substitution_quarter_image(sisi)
        assert o1 == 0xfd45c240
        assert o2 == 0x3d63cf73
        assert o3 == 0x07647db9
        assert o4 == 0x56c8c391

    def test_function1(self):
        sisi = 942674285
        kr = 12
        km = 1098270977
        output = function1(sisi, kr, km)
        assert output == 1854126923

    def test_function2(self):
        sisi = 942674285
        kr = 12
        km = 1098270977
        output = function2(sisi, kr, km)
        assert output == 1848952271

    def test_function3(self):
        sisi = 942674285
        kr = 12
        km = 1098270977
        output = function3(sisi, kr, km)
        assert output == 3059868540
