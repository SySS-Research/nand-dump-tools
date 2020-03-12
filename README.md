# NAND Dump Tools

The SySS NAND Dump Tools are a collection of software tools for working with raw NAND flash memory dumps and images.

By using error-correcting codes, for instance [BCH codes (Bose–Chaudhuri–Hocquenghem Codes)](https://en.wikipedia.org/wiki/BCH_code), supporting different configurations, the **NAND Dump Decoder** can create error-corrected data dumps from raw NAND flash memory dumps, which can then be used with other tools, for instance the [ubireader tools](https://github.com/jrspruitt/ubi_reader).

The **NAND Dump Encoder** can be used to create raw NAND flash memory images from binary input files for supported target platforms, which can then be directly written to corresponding NAND memory chips.

The NAND Dump Tools are based on and inspired by the open source software tool [PMECC Reader and Decoder](https://www.mickaelwalter.fr/2018/06/08/dumping-a-slc-nand-flash-with-atmel-pmecc/) by Mickaël Walter ([@MickaelWalter](https://twitter.com/MickaelWalter)).

## Installation

The NAND Dump Tools can be downloaded and installed in the following way:

```
git clone https://github.com/SySS-Research/nand-dump-tools.git
cd NAND_Dump_Tools
./setup.sh
```

## Usage

The Python tools **NAND Dump Decoder** and **NAND Dump Encoder** can be used via Shell script wrappers which automatically use the virtual environment for Python created during the software installation.

The following output shows the help screen of the **NAND Dump Decoder**:

```
$ ./nand_dump_decoder.sh --help
 _   _   ___   _   _______  ______                        ______                   _          
| \ | | / _ \ | \ | |  _  \ |  _  \                       |  _  \                 | |         
|  \| |/ /_\ \|  \| | | | | | | | |_   _ _ __ ___  _ __   | | | |___  ___ ___   __| | ___ _ __
| . ` ||  _  || . ` | | | | | | | | | | | '_ ` _ \| '_ \  | | | / _ \/ __/ _ \ / _` |/ _ \ '__|
| |\  || | | || |\  | |/ /  | |/ /| |_| | | | | | | |_) | | |/ /  __/ (_| (_) | (_| |  __/ |  
\_| \_/\_| |_/\_| \_/___/   |___/  \__,_|_| |_| |_| .__/  |___/ \___|\___\___/ \__,_|\___|_|  
                                                  | |                                         
                                                  |_|                                         
NAND Dump Decoder v0.2 by Matthias Deeg - SySS GmbH (c) 2018-2020
---
usage: nand_dump_decoder.py [-h] -i INFOLDER -o OUTFILE [-c CONFIG] [-m MODE] [--atmel-config] [--nxp-fcb-config]
 
optional arguments:
  -h, --help            show this help message and exit
  -i INFOLDER, --infolder INFOLDER
                        Input folder with binary dump files (.bin)
  -o OUTFILE, --outfile OUTFILE
                        Output dump file
  -c CONFIG, --config CONFIG
                        Configuration file
  -m MODE, --mode MODE  Vendor specific NAND mode (ATMEL, NXP_IMX28
  --atmel-config        Retrieve ATMEL config from first page of the dump file
  --nxp-fcb-config      Retrieve NXP config from firmware control block (FCB) of first page of the dump file
```

The following output shows the help screen of the **NAND Dump Encoder**:

```
$ ./nand_dump_encoder.sh --help
 _   _   ___   _   _______  ______                         _____                    _          
| \ | | / _ \ | \ | |  _  \ |  _  \                       |  ___|                  | |         
|  \| |/ /_\ \|  \| | | | | | | | |_   _ _ __ ___  _ __   | |__ _ __   ___ ___   __| | ___ _ __
| . ` ||  _  || . ` | | | | | | | | | | | '_ ` _ \| '_ \  |  __| '_ \ / __/ _ \ / _` |/ _ \ '__|
| |\  || | | || |\  | |/ /  | |/ /| |_| | | | | | | |_) | | |__| | | | (_| (_) | (_| |  __/ |  
\_| \_/\_| |_/\_| \_/___/   |___/  \__,_|_| |_| |_| .__/  \____/_| |_|\___\___/ \__,_|\___|_|  
                                                  | |                                          
                                                  |_|                                          
NAND Dump Encoder v0.2 by Matthias Deeg - SySS GmbH (c) 2018-2020
---
usage: nand_dump_encoder.py [-h] -i INFILE -o OUTFILE [-c CONFIG] [--atmel-config] [-k KEY]
 
optional arguments:
  -h, --help            show this help message and exit
  -i INFILE, --infile INFILE
                        Input file
  -o OUTFILE, --outfile OUTFILE
                        Output dump file
  -c CONFIG, --config CONFIG
                        Configuration file
  --atmel-config        Use ATMEL config in first page of the dump file
  -k KEY, --key KEY     Crypto key for ATMEL ECC encryption
```

## Example

The following example shows how the errors of a raw NAND flash memory dump of a [SAMA5D4 Xplained Ultra evaluation board](https://www.microchip.com/DevelopmentTools/ProductDetails/ATSAMA5D4-XULT) with a MT29F4G08 NAND flash memory chip (device ID 2CDC90A6) are corrected using the NAND Dump Decoder.
The configuration of the ATMEL target system is read from the dump itself (PMECC header in first NAND dump block) using the command line argument **--atmel-config**. Alternatively, the command line argument **--config** can be used to specify a suitable NAND configuration.

```
$ ./nand_dump_decoder.sh -i ~/dump/SAMA5D4/dump1 -o sama.bin --atmel-config
 _   _   ___   _   _______  ______                        ______                   _                                                                                                                                
| \ | | / _ \ | \ | |  _  \ |  _  \                       |  _  \                 | |                                                                                                                               
|  \| |/ /_\ \|  \| | | | | | | | |_   _ _ __ ___  _ __   | | | |___  ___ ___   __| | ___ _ __                                                                                                                      
| . ` ||  _  || . ` | | | | | | | | | | | '_ ` _ \| '_ \  | | | / _ \/ __/ _ \ / _` |/ _ \ '__|                                                                                                                     
| |\  || | | || |\  | |/ /  | |/ /| |_| | | | | | | |_) | | |/ /  __/ (_| (_) | (_| |  __/ |                                                                                                                        
\_| \_/\_| |_/\_| \_/___/   |___/  \__,_|_| |_| |_| .__/  |___/ \___|\___\___/ \__,_|\___|_|                                                                                                                        
                                                  | |                                                                                                                                                               
                                                  |_|                                                                                                                                                               
NAND Dump Decoder v0.2 by Matthias Deeg - SySS GmbH (c) 2018-2020                                        
---                                                 
[*] Found one binary input file (566231040 bytes)                                                        
[*] Using ECC mode ATMEL                            
[*] Used configuration                              
    Block size:  262144 bytes (64 pages)                                                                 
    Page size:   4096 bytes                         
    Sector size: 512 bytes                          
    Spare size:  224 bytes                          
    ECC offset:  120 bytes                          
    ECC errors:  8 errors per sector (max.)                                                              
    ECC bytes:   13 bytes per sector                
    Use ECC:     True                               
    File offset: 0x0 (skip 0 blocks)                
[*] Search for ECC crypto key ...                   
[*] Found ECC crypto key: f78a7490b7c95943e99ea724ad                                                     
[*] Starting error correcting process ...                                                                
    Progress: 100.00% (1048576/1048576 sectors)                                                          
[*] Completed error correcting process              
    Successfully written 536870912 bytes of data to output file 'sama.bin'                               
    -----                                           
    Some statistics                                 
    Total pages:        131072                      
    Blank pages:        90846 (69.31%)              
    Blank sectors:      726768 (69.31%)                                                                  
    Data sectors:       321808 (30.69%)                                                                  
    Total sectors:      1048576                     
    Valid sectors:      1048576 (100.00%)                                                                
    Valid data sectors: 321808 (30.69%)                                                                  
    Corrupted sectors:  0 (0.00%)                   
    Corrected sectors:  2 (0.00%)                   
    Bad blocks:         0
```

Besides an error-corrected data dump, in this example, the NAND Dump Decoder also extracts a found cryptographic key which is used by some target systems for encrypting the error-correcting codes within the NAND spare areas, like in our SAMA5D4 device.

The created error-corrected NAND dump contains only data of user areas and can be used with the Memory Technology Device (MTD) System for Linux and its NAND simulator in the following way:

```
modprobe nandsim first_id_byte=0x2C second_id_byte=0xdc third_id_byte=0x90 fourth_id_byte=0xa6
 
cat /proc/mtd
 
nandwrite /dev/mtd1 sama.bin
```

If the NAND flash memory dump contains an Unsorted Block Image (UBI) with a UBI file system (UBIFS), like in this example, it can be mounted as follows:

```
modprobe ubi mtd=/dev/mtd1,4096
 
mkdir /tmp/nand_dump
 
mount -t ubifs -o rw /dev/ubi0_0 /tmp/nand_dump
```

By using the software tool [ubireader_utils_info](https://github.com/jrspruitt/ubi_reader), the corresponding configuration of the Unsorted Block Image can be extracted, as the following output shows:

```
$ ubireader_utils_info sama.bin
 
Volume rootfs
        alignment       -a 1
        default_compr   -x lzo
        fanout          -f 8
        image_seq       -Q 928361211
        key_hash        -k r5
        leb_size        -e 253952
        log_lebs        -l 4
        max_bud_bytes   -j 8388608
        max_leb_cnt     -c 2082
        min_io_size     -m 4096
        name            -N rootfs
        orph_lebs       -p 1
        peb_size        -p 262144
        sub_page_size   -s 4096
        version         -x 1
        vid_hdr_offset  -O 4096
        vol_id          -n 0
 
        #ubinize.ini#
        [rootfs]
        vol_type=dynamic
        vol_flags=0
        vol_id=0
        vol_name=rootfs
        vol_alignment=1
        vol_size=500285440
Writing to: ubifs-root/sama.bin/img-928361211/create_ubi_img-928361211.sh
Writing to: ubifs-root/sama.bin/img-928361211/img-928361211.ini
```

With this information, an Unsorted Block Image with the correctly formatted UBIFS can be created in the following way:

```
mkfs.ubifs -m 4096 -e 253952 -c 2082 -x lzo -f 8 -k r5 -p 1 -l 4 -r /tmp/nand_dump/ sama_hacked.ubifs
 
ubinize -p 262144 -m 4096 -O 4096 -s 4096 -x 1 -Q 928361211 -o sama_hacked.ubi sama_hacked.ini
```

Before such a created UBI file is further processed, its size should be adjusted via padding with 0xFF bytes to match the specification of the corresponding NAND memory chip, for instance 536870912 bytes for the 512 MB MT29F4G08.
In doing so, there won't be any problems when programming the NAND chip with a universal programmer like the [UP-828P](https://www.teeltech.com/mobile-device-forensic-hardware/up-828-programmer/).

Now, a valid NAND flash memory image can be created with the NAND Dump Encoder using a suitable configuration for the target system (SAMA5D4 in this example) and the correct cryptographic key for encrypting the error-correcting BCH codes within the NAND spare areas.

```
$ ./nand_dump_encoder.sh -i hacked_dump.bin -o hacked_sama_image.bin -c conf/29F4G08_Micron_ATMEL.conf -k f78a7490b7c95943e99ea724ad
                                                                                   
 _   _   ___   _   _______  ______                         _____                    _
| \ | | / _ \ | \ | |  _  \ |  _  \                       |  ___|                  | |
|  \| |/ /_\ \|  \| | | | | | | | |_   _ _ __ ___  _ __   | |__ _ __   ___ ___   __| | ___ _ __
| . ` ||  _  || . ` | | | | | | | | | | | '_ ` _ \| '_ \  |  __| '_ \ / __/ _ \ / _` |/ _ \ '__|
| |\  || | | || |\  | |/ /  | |/ /| |_| | | | | | | |_) | | |__| | | | (_| (_) | (_| |  __/ |
\_| \_/\_| |_/\_| \_/___/   |___/  \__,_|_| |_| |_| .__/  \____/_| |_|\___\___/ \__,_|\___|_|
                                                  | |
                                                  |_|
NAND Dump Encoder v0.2 by Matthias Deeg - SySS GmbH (c) 2018-2020
---
[*] Found input file with a file size of 536870912 bytes
[*] Read configuration file 'conf/29F4G08_Micron_ATMEL.conf'
[*] Used configuration
    Block size:  262144 bytes (64 pages)
    Page size:   4096 bytes
    Sector size: 512 bytes
    Spare size:  224 bytes
    ECC offset:  120 bytes
    ECC errors:  8 errors per sector (max.)
    ECC bytes:   13 bytes per sector
    Use ECC:     True
[*] Generating output file ...
    Progress: 100.00% (1048576/1048576 sectors)
[*] Completed error correcting process
    Successfully written 536870912 bytes of data to output file 'hacked_sama_image.bin'
    -----
    Some statistics
    Total pages:        131072
    Blank pages:        92445 (70.53%)
    Blank sectors:      739560 (70.53%)
    Data sectors:       309016 (29.47%)
    Total sectors:      1048576
    Bad blocks:         0
```

## Demo

This demo video exemplarily shows a chip-off/chip-on attack for gaining unauthorized root access on a SAMA5D4 device ([SAMA5D4 Xplained Ultra evaluation board](https://www.microchip.com/DevelopmentTools/ProductDetails/ATSAMA5D4-XULT)) by exploiting the unencrypted NAND flash memory.

[![SySS PoC Video: Exploiting the Obvious But Not the Trivial - Unencrypted NAND Flash Memory](/images/exploiting_unencrypted_nand_poc_video.jpg)](https://www.youtube.com/watch?v=eTtfRDMjgww "Exploiting the Obvious But Not the Trivial - Unencrypted NAND Flash Memory")

## To-do
* improve speed ;-) 

## References

* [BCH codes](https://en.wikipedia.org/wiki/BCH_code), Wikipedia, 2020 
* [PMECC Reader and Decoder](https://www.mickaelwalter.fr/2018/06/08/dumping-a-slc-nand-flash-with-atmel-pmecc/), Mickaël Walter, 2018
* [SAMA5D4 Xplained Ultra](https://www.microchip.com/DevelopmentTools/ProductDetails/ATSAMA5D4-XULT), Microchip
* [UP-828P](https://www.teeltech.com/mobile-device-forensic-hardware/up-828-programmer/)

## Disclaimer

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.
