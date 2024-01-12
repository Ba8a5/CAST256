import unittest

from utils import *

val1 = 2 ** 32 - 1
val2 = 2 ** 32 // 2
val3 = 2 ** 32 // 4
val4 = 2 ** 32 // 8


class TestArithmetic(unittest.TestCase):

    def test_sum_no_mod(self):
        a = 2 ** 32 // 2
        b = a - 5
        expected = 2 ** 32 - 5
        result = sum_mod_232(a, b)
        assert result == expected

    def test_sum_mod(self):
        a = 2 ** 32 // 2
        b = a + 1
        expected = 1
        result = sum_mod_232(a, b)
        assert result == expected

    def test_diff_no_mod(self):
        a = 2 ** 32 // 2
        b = a - 5
        expected = 5
        result = diff_mod_232(a, b)
        assert result == expected

    def test_diff_mod(self):
        a = 2 ** 32 // 2
        b = a + 1
        expected = 2 ** 32 - 1
        result = diff_mod_232(a, b)
        assert result == expected

    def test_build128From32(self):
        result = build_128_bit_bloc_from_32_bit_blocs(val1, val2, val3, val4)
        assert result == val1 * 2 ** (32 * 3) + val2 * 2 ** (32 * 2) + val3 * 2 ** 32 + val4

    def test_extract_32bit_bloc_from_128(self):
        result = build_128_bit_bloc_from_32_bit_blocs(val1, val2, val3, val4)
        a, b, c, d = extract_32bit_bloc_from_128(result)
        assert a == val1
        assert b == val2
        assert c == val3
        assert d == val4

    def test_build256From32(self):
        result = build_256_bit_bloc_from_32_bit_blocs(val1, val2, val3, val4, val1, val2, val3, val4)
        value128 = val1 * 2 ** (32 * 3) + val2 * 2 ** (32 * 2) + val3 * 2 ** 32 + val4
        assert result == value128 * 2 ** 128 + value128

    def test_extract_32bit_bloc_from_256(self):
        result = build_256_bit_bloc_from_32_bit_blocs(val1, val2, val3, val4, val1, val2, val3, val4)
        a, b, c, d, e, f, g, h = extract_32bit_bloc_from_256(result)
        assert a == val1
        assert b == val2
        assert c == val3
        assert d == val4
        assert e == val1
        assert f == val2
        assert g == val3
        assert h == val4

    def test_extract_8bit_bloc_from_32(self):
        a, b, c, d = extract_8bit_blocs_from_32(942674285)
        assert a == 56
        assert b == 48
        assert c == 17
        assert d == 109

    def test_shift_left_4bits(self):
        init = 0b1010
        final = shift_left(init, 4, 1)
        expected = 0b0101
        assert expected == final

        final = shift_left(final, 4, 1)
        expected = 0b1010
        assert expected == final

    def test_shift_left_7bits(self):
        init = 0b1010111
        final = shift_left(init, 7, 1)
        expected = 0b0101111
        assert expected == final

        final = shift_left(final, 7, 1)
        expected = 0b1011110
        assert expected == final

    def test_shift_left_7bits_3bits(self):
        init = 0b1010111
        final = shift_left(init, 7, 3)
        expected = 0b0111101
        assert expected == final

    def test_shift_left_32bits_12bits(self):
        init = 0x12345678
        final = shift_left(init, 32, 12)
        expected = 0x45678123
        assert expected == final
