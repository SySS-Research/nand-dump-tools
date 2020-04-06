#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  YAFFS ECC

  Error correction for Yet Another Flash File System (YAFFS)
  created by Charles Manning <charles@aleph1.co.uk>

  Ported to Python by Matthias Deeg <matthias.deeg@syss.de>

  MIT License

  Copyright (C) 2002-2011 Aleph One Ltd.
  Copyright (c) 2020 SySS GmbH

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
"""

__version__ = '0.1'
__author__ = 'Matthias Deeg'

# bit count lookup table
YAFFS_COUNT_BITS_TABLE = [
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
]

# column parity lookup table for Hamming ECC
COLUMN_PARITY_TABLE = [
    0x00, 0x55, 0x59, 0x0c, 0x65, 0x30, 0x3c, 0x69,
    0x69, 0x3c, 0x30, 0x65, 0x0c, 0x59, 0x55, 0x00,
    0x95, 0xc0, 0xcc, 0x99, 0xf0, 0xa5, 0xa9, 0xfc,
    0xfc, 0xa9, 0xa5, 0xf0, 0x99, 0xcc, 0xc0, 0x95,
    0x99, 0xcc, 0xc0, 0x95, 0xfc, 0xa9, 0xa5, 0xf0,
    0xf0, 0xa5, 0xa9, 0xfc, 0x95, 0xc0, 0xcc, 0x99,
    0x0c, 0x59, 0x55, 0x00, 0x69, 0x3c, 0x30, 0x65,
    0x65, 0x30, 0x3c, 0x69, 0x00, 0x55, 0x59, 0x0c,
    0xa5, 0xf0, 0xfc, 0xa9, 0xc0, 0x95, 0x99, 0xcc,
    0xcc, 0x99, 0x95, 0xc0, 0xa9, 0xfc, 0xf0, 0xa5,
    0x30, 0x65, 0x69, 0x3c, 0x55, 0x00, 0x0c, 0x59,
    0x59, 0x0c, 0x00, 0x55, 0x3c, 0x69, 0x65, 0x30,
    0x3c, 0x69, 0x65, 0x30, 0x59, 0x0c, 0x00, 0x55,
    0x55, 0x00, 0x0c, 0x59, 0x30, 0x65, 0x69, 0x3c,
    0xa9, 0xfc, 0xf0, 0xa5, 0xcc, 0x99, 0x95, 0xc0,
    0xc0, 0x95, 0x99, 0xcc, 0xa5, 0xf0, 0xfc, 0xa9,
    0xa9, 0xfc, 0xf0, 0xa5, 0xcc, 0x99, 0x95, 0xc0,
    0xc0, 0x95, 0x99, 0xcc, 0xa5, 0xf0, 0xfc, 0xa9,
    0x3c, 0x69, 0x65, 0x30, 0x59, 0x0c, 0x00, 0x55,
    0x55, 0x00, 0x0c, 0x59, 0x30, 0x65, 0x69, 0x3c,
    0x30, 0x65, 0x69, 0x3c, 0x55, 0x00, 0x0c, 0x59,
    0x59, 0x0c, 0x00, 0x55, 0x3c, 0x69, 0x65, 0x30,
    0xa5, 0xf0, 0xfc, 0xa9, 0xc0, 0x95, 0x99, 0xcc,
    0xcc, 0x99, 0x95, 0xc0, 0xa9, 0xfc, 0xf0, 0xa5,
    0x0c, 0x59, 0x55, 0x00, 0x69, 0x3c, 0x30, 0x65,
    0x65, 0x30, 0x3c, 0x69, 0x00, 0x55, 0x59, 0x0c,
    0x99, 0xcc, 0xc0, 0x95, 0xfc, 0xa9, 0xa5, 0xf0,
    0xf0, 0xa5, 0xa9, 0xfc, 0x95, 0xc0, 0xcc, 0x99,
    0x95, 0xc0, 0xcc, 0x99, 0xf0, 0xa5, 0xa9, 0xfc,
    0xfc, 0xa9, 0xa5, 0xf0, 0x99, 0xcc, 0xc0, 0x95,
    0x00, 0x55, 0x59, 0x0c, 0x65, 0x30, 0x3c, 0x69,
    0x69, 0x3c, 0x30, 0x65, 0x0c, 0x59, 0x55, 0x00,
]


def calc_even_parity(data, size=8):
    """Calc even parity bit of given data"""

    parity = 0
    for i in range(size):
        parity = parity ^ ((data >> i) & 1)

    return parity


def yaffs_hweight8(byte):
    return YAFFS_COUNT_BITS_TABLE[byte]


def yaffs_hweight32(dword):
    return yaffs_hweight8(dword & 0xff) + \
        yaffs_hweight8((dword >> 8) & 0xff) + \
        yaffs_hweight8((dword >> 16) & 0xff) + \
        yaffs_hweight8((dword >> 24) & 0xff)


def yaffs_calc_ecc_256(data):
    """Calc YAFFS ECC for 256 byte input"""

    ecc = [0] * 3
    col_parity = 0
    line_parity = 0
    line_parity_prime = 0

    for i in range(256):
        b = COLUMN_PARITY_TABLE[data[i]]
        col_parity ^= b

        if (b & 0x01):                      # odd number of bits in the byte
            line_parity ^= i
            line_parity_prime ^= ~i

    ecc[2] = (~col_parity & 0xff) | 0x03

    t = 0
    if (line_parity & 0x08):
        t |= 0x80
    if (line_parity_prime & 0x08):
        t |= 0x40
    if (line_parity & 0x04):
        t |= 0x20
    if (line_parity_prime & 0x04):
        t |= 0x10
    if (line_parity & 0x02):
        t |= 0x08
    if (line_parity_prime & 0x02):
        t |= 0x04
    if (line_parity & 0x01):
        t |= 0x02
    if (line_parity_prime & 0x01):
        t |= 0x01
    ecc[1] = ~t & 0xff

    t = 0
    if (line_parity & 0x80):
        t |= 0x80
    if (line_parity_prime & 0x80):
        t |= 0x40
    if (line_parity & 0x40):
        t |= 0x20
    if (line_parity_prime & 0x40):
        t |= 0x10
    if (line_parity & 0x20):
        t |= 0x08
    if (line_parity_prime & 0x20):
        t |= 0x04
    if (line_parity & 0x10):
        t |= 0x02
    if (line_parity_prime & 0x10):
        t |= 0x01
    ecc[0] = ~t & 0xff

    return ecc


def yaffs_ecc_correct(data, read_ecc, test_ecc):
    """Correct single bit error"""

    corrected = [0] * len(data)

    # deltas
    d0 = read_ecc[0] ^ test_ecc[0]
    d1 = read_ecc[1] ^ test_ecc[1]
    d2 = read_ecc[2] ^ test_ecc[2]

    if ((d0 | d1 | d2) == 0):
        # there is no error
        return (0, data, read_ecc)

    # check for single bit error
    if (((d0 ^ (d0 >> 1)) & 0x55) == 0x55 and
        ((d1 ^ (d1 >> 1)) & 0x55) == 0x55 and
        ((d2 ^ (d2 >> 1)) & 0x54) == 0x54):

        bit = 0
        byte = 0

        if (d1 & 0x80):
            byte |= 0x80
        if (d1 & 0x20):
            byte |= 0x40
        if (d1 & 0x08):
            byte |= 0x20
        if (d1 & 0x02):
            byte |= 0x10
        if (d0 & 0x80):
            byte |= 0x08
        if (d0 & 0x20):
            byte |= 0x04
        if (d0 & 0x08):
            byte |= 0x02
        if (d0 & 0x02):
            byte |= 0x01

        if (d2 & 0x80):
            bit |= 0x04
        if (d2 & 0x20):
            bit |= 0x02
        if (d2 & 0x08):
            bit |= 0x01

        corrected[byte] ^= (1 << bit) & 0xff

        # corrected single bit error in data
        return (1, corrected, read_ecc)

    # check for recoverable error in ECC
    if ((yaffs_hweight8(d0) + yaffs_hweight8(d1) + yaffs_hweight8(d2)) == 1):

        read_ecc[0] = test_ecc[0]
        read_ecc[1] = test_ecc[1]
        read_ecc[2] = test_ecc[2]

        # corrected single bit error in ECC
        return (1, data, read_ecc)

    # unrecoverable error
    return (-1, data, read_ecc)


def yaffs_extract_ecc(data, ecc_size, ecc_count, ignore_byte=0xff):
    """Extract ECC from spare area using a heuristic"""

    pos = 0
    result = []
    # offset of ECC in spare area is variable, more info required
    for pos in range(8, len(data)):
        if data[pos] != ignore_byte:
            break

    if pos + (ecc_size * ecc_count) > len(data):
        return result

    for i in range(ecc_count):
        ecc = [0] * 3
        ecc[0] = data[pos + (i * ecc_size)]
        ecc[1] = data[pos + (i * ecc_size) + 1]
        ecc[2] = data[pos + (i * ecc_size) + 2]
        result.append(ecc)

    return result

