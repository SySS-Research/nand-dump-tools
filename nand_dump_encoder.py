#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  NAND Dump Encoder

  Simple software tool for encoding raw dumps for NAND memory chips using
  implemented error correcting codes (ECC) like BCH
  by Matthias Deeg <matthias.deeg@syss.de>

  uses BCH library for Python (python-bchlib) by Jeff Kent
  https://github.com/jkent/python-bchlib

  MIT License

  Copyright (c) 2018-2020 SySS GmbH

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

__version__ = '0.2'
__author__ = 'Matthias Deeg'

import argparse
import configparser
import bchlib
import os
import struct
import sys

from binascii import unhexlify

#  BCH polynom
ECC_POLY1 = 0x201b       # 8219
ECC_POLY2 = 0x4443       # 17475

# binary dump file extension
DUMP_FILE_EXTENSION = ".bin"


def read_bits(value, low, high, bits=8):
    format_str = "0{:d}b".format(bits)

    n = format(value, format_str)[::-1]
    return int(n[low:high][::-1], 2)


def reverse_bits(data):
    reversed_value = b''
    for i in range(0, len(data)):
        reversed_value += bytes([int('{:08b}'.format(data[i])[::-1], 2)])
    return reversed_value


def xor_crypto(data, key):
    return bytes(a ^ b for a, b in zip(data, key))


def read_atmel_config(page, config):
    """Read ATMEL PMECC configuration from first page"""

    # read ATMEL PMECC header (52 times at the beginning of the first page)
    header = struct.unpack("<L", page[:4])[0]

    # header key
    key = read_bits(header, 28, 32, 32)

    if key != 0x0C:
        print("[-] Error: ATMEL configuration header incorrect")
        sys.exit(1)

    # PMECC usage flag
    config['useecc'] = (read_bits(header, 0, 1, 32) == 1)

    # sector per page
    v = read_bits(header, 1, 4, 31)

    # spare area size
    config['spareareasize'] = read_bits(header, 4, 13, 32)

    # eccBitReq
    v = read_bits(header, 13, 16, 32)

    if v == 0:
        config['ecc_errors'] = 2
    elif v == 1:
        config['ecc_errors'] = 4
    elif v == 2:
        config['ecc_errors'] = 8
    elif v == 3:
        config['ecc_errors'] = 12
    elif v == 4:
        config['ecc_errors'] = 24

    # sector size
    v = read_bits(header, 16, 18, 32)

    if v == 0:
        config['sectorsize'] = 512

        # set required ECC bytes per sector
        if config['ecc_errors'] == 2:
            config['ecc_bytes_per_sector'] = 4
        elif config['ecc_errors'] == 4:
            config['ecc_bytes_per_sector'] = 7
        elif config['ecc_errors'] == 8:
            config['ecc_bytes_per_sector'] = 13
        elif config['ecc_errors'] == 12:
            config['ecc_bytes_per_sector'] = 20
        elif config['ecc_errors'] == 24:
            config['ecc_bytes_per_sector'] = 39

    elif v == 1:
        config['sectorsize'] = 1024

        # set required ECC bytes per sector
        if config['ecc_errors'] == 2:
            config['ecc_bytes_per_sector'] = 4
        elif config['ecc_errors'] == 4:
            config['ecc_bytes_per_sector'] = 7
        elif config['ecc_errors'] == 8:
            config['ecc_bytes_per_sector'] = 14
        elif config['ecc_errors'] == 12:
            config['ecc_bytes_per_sector'] = 21
        elif config['ecc_errors'] == 24:
            config['ecc_bytes_per_sector'] = 42

    # ECC offset in spare area
    config['ecc_offset'] = read_bits(header, 18, 27, 32)

    # header key
    key = read_bits(header, 28, 32, 32)

    if key != 0x0C:
        print("[-] Error: Header incorrect")
        sys.exit(1)

    return config


def atmel_generate_ecc_data(infile, outfile, config, crypto_key):
    """Generate ECC data and resulting dump file for ATMEL"""

    # initialize BCH encoder
    bch = bchlib.BCH(config['ecc_polynom'], config['ecc_errors'], False)

    # open output file
    fout = open(outfile, "wb")

    # open input file
    fin = open(infile, "rb")

    # initialize some variables
    processed_sector_count = 0
    data_sector_count = 0
    blank_page_count = 0
    total_page_count = config['filesize'] // config['pagesize']
    sectors_per_page = config['pagesize'] // config['sectorsize']
    total_sectors = total_page_count * sectors_per_page
    ecc_bytes_total = sectors_per_page * config['ecc_bytes_per_sector']

    # blank page data
    blank_page = b'\xff' * config['pagesize']

    # blank spare area data
    blank_spare_area = b'\xff' * config['spareareasize']

    # spare bytes before and after ECC data
    spare_area1 = b'\xff' * config['ecc_offset']
    spare_area2 = b'\xff' * (config['spareareasize'] - config['ecc_offset'] -
                             ecc_bytes_total)

    print("[*] Generating output file ...")
    for page in range(total_page_count):
        # read current block data
        page_data = fin.read(config['pagesize'])

        processed_sector_count += sectors_per_page

        if page_data == blank_page:
            # increment blank page counter
            blank_page_count += 1

            # write blank page data and blank spare area data
            fout.write(page_data + blank_spare_area)

        else:
            # increment data sector counter
            data_sector_count += sectors_per_page

            # generate ECC for each sector
            eccs = b''

            for sector in range(sectors_per_page):
                start_sector = sector * config['sectorsize']
                end_sector = start_sector + config['sectorsize']
                sector_data = reverse_bits(page_data[start_sector:end_sector])

                ecc = bch.encode(sector_data)

                # encrypt ECC
                # key = unhexlify("F78A7490B7C95943E99EA724AD")
                ecc_encrypted = xor_crypto(reverse_bits(ecc), crypto_key)

                eccs += ecc_encrypted
                # eccs += reverse_bits(ecc_encrypted)

            spare_area_data = spare_area1 + eccs + spare_area2
            fout.write(page_data + spare_area_data)

        # show some statistics during processing all sectors
        progress = processed_sector_count / total_sectors * 100
        print("\r    Progress: {:.2f}% ({}/{} sectors)"
              .format(progress, processed_sector_count, total_sectors), end="")

    # close output file
    fout.close()

    # close input file
    fin.close()

    # show some statistics at the end
    blank_page_percentage = blank_page_count / total_page_count * 100
    blank_sector_count = blank_page_count * sectors_per_page
    blank_sector_percentage = blank_sector_count / total_sectors * 100
    data_sector_percentage = data_sector_count / total_sectors * 100
    bad_block_count = 0

    print("\n[*] Completed error correcting process")
    print("    Successfully written {} bytes of data to output file '{}'"
          .format(config['sectorsize'] * total_sectors, outfile))
    print("    -----\n    Some statistics\n"
          "    Total pages:        {}\n"
          "    Blank pages:        {} ({:.2f}%)\n"
          "    Blank sectors:      {} ({:.2f}%)\n"
          "    Data sectors:       {} ({:.2f}%)\n"
          "    Total sectors:      {}\n"
          "    Bad blocks:         {}"
          .format(total_page_count, blank_page_count, blank_page_percentage,
                  blank_sector_count, blank_sector_percentage,
                  data_sector_count, data_sector_percentage,
                  total_sectors, bad_block_count))


def show_config(config):
    """Show configuration"""

    print("[*] Used configuration\n"
          "    Block size:  {} bytes ({} pages)\n"
          "    Page size:   {} bytes\n"
          "    Sector size: {} bytes\n"
          "    Spare size:  {} bytes\n"
          "    ECC offset:  {} bytes\n"
          "    ECC errors:  {} errors per sector (max.)\n"
          "    ECC bytes:   {} bytes per sector\n"
          "    Use ECC:     {}"
          .format(config['blocksize'] * config['pagesize'],
                  config['blocksize'], config['pagesize'],
                  config['sectorsize'], config['spareareasize'],
                  config['ecc_offset'], config['ecc_errors'],
                  config['ecc_bytes_per_sector'], config['useecc']))


def banner():
    """Show a fancy banner"""
    print(
""" _   _   ___   _   _______  ______                         _____                    _           \n"""
"""| \ | | / _ \ | \ | |  _  \ |  _  \                       |  ___|                  | |          \n"""
"""|  \| |/ /_\ \|  \| | | | | | | | |_   _ _ __ ___  _ __   | |__ _ __   ___ ___   __| | ___ _ __ \n"""
"""| . ` ||  _  || . ` | | | | | | | | | | | '_ ` _ \| '_ \  |  __| '_ \ / __/ _ \ / _` |/ _ \ '__|\n"""
"""| |\  || | | || |\  | |/ /  | |/ /| |_| | | | | | | |_) | | |__| | | | (_| (_) | (_| |  __/ |   \n"""
"""\_| \_/\_| |_/\_| \_/___/   |___/  \__,_|_| |_| |_| .__/  \____/_| |_|\___\___/ \__,_|\___|_|   \n"""
"""                                                  | |                                           \n"""
"""                                                  |_|                                           \n"""
"""NAND Dump Encoder v{0} by Matthias Deeg - SySS GmbH (c) 2018-2020\n---""".format(__version__))


# main program
if __name__ == '__main__':
    # show banner
    banner()

    # init argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--infile', type=str, help='Input file', required=True)
    parser.add_argument('-o', '--outfile', type=str, help='Output dump file', required=True)
    parser.add_argument('-c', '--config', type=str, help='Configuration file')
    parser.add_argument('--atmel-config', action="store_true", help='Use ATMEL config in first page of the dump file')
    parser.add_argument('-k', '--key', type=str, help='Crypto key for ATMEL ECC encryption')

    # parse arguments
    args = parser.parse_args()

    # create empty configuration
    config = {}

    # check input file
    if os.path.exists(args.infile):
        infile_size = os.path.getsize(args.infile)
        config['filesize'] = infile_size
        print("[*] Found input file with a file size of {} bytes".format(infile_size))
    else:
        print("[-] Error: Could not find input file '{}'".format(args.infile))
        sys.exit(1)

    # check if ATMEL configuration within NAND dump should be used
    if args.atmel_config:
        # set some default ATMEL configuration parameters
        config['blocksize'] = 64
        config['pagesize'] = 2048
        config['sectorsize'] = 512
        config['spareareasize'] = 64
        config['ecc_errors'] = 4
        config['ecc_polynom'] = ECC_POLY1
        config['fullpagesize'] = config['pagesize'] + config['spareareasize']

        # read ATMEL PMECC configuration from first page of first input file
        with open(args.infile, "rb") as f:
            first_page = f.read(config['fullpagesize'])
            config = read_atmel_config(first_page, config)
    else:
        # read configuration from given config file
        if not os.path.isfile(args.config):
            print("[-] Error: Config file '{}' does not exist".format(args.config))
            sys.exit(1)

        print("[*] Read configuration file '{}'".format(args.config))
        configfile = configparser.ConfigParser()
        try:
            configfile.read(args.config)

            # convert data types of parsed config data
            config['blocksize'] = int(configfile['default']['blocksize'])
            config['pagesize'] = int(configfile['default']['pagesize'])
            config['sectorsize'] = int(configfile['default']['sectorsize'])
            config['spareareasize'] = int(configfile['default']['spareareasize'])
            config['useecc'] = bool(configfile['default']['useecc'])
            config['ecc_offset'] = int(configfile['default']['ecc_offset'])
            config['ecc_errors'] = int(configfile['default']['ecc_errors'])
            config['ecc_polynom'] = int(configfile['default']['ecc_polynom'], 16)
            config['ecc_errors'] = int(configfile['default']['ecc_errors'])
            config['ecc_bytes_per_sector'] = int(configfile['default']['ecc_bytes_per_sector'])

        except KeyError:
            sys.exit("[-] Error: Could not read all required configuration values")

    # add derivated configuration parameters
    config['fullpagesize'] = config['pagesize'] + config['spareareasize']

    # check crypto key
    if args.key is not None:
        crypto_key = unhexlify(args.key)
    else:
        # set default null byte crypto key
        crypto_key = b"\x00" * config['ecc_bytes_per_sector']

    # show config
    show_config(config)

    if config['useecc']:
        atmel_generate_ecc_data(args.infile, args.outfile, config, crypto_key)
