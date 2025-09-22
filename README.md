# KeePass2 to John the Ripper Converter

## Introduction
This script extracts the outer headers of a KDBX 4 file and formats the relevant parameters into a structure compatible with John the Ripper (JtR) password cracker and **as of Hashcat 7.1** it should also be compatible with mode 34300!

**Important Notes:**
- This script is **only compatible** with KDBX 4 files using **Argon2** as the Key Derivation Function (KDF).
- Although this script converts the KDBX file into a format readable by John the Ripper, **brute-forcing Argon2-protected databases is currently not practical due to high computational costs**.
- John the Ripper already provides a similar script written in C ([Keepass2John.c](https://github.com/openwall/john/blob/bleeding-jumbo/src/keepass2john.c)), but this Python implementation aims to improve ease of use and code readability.

This script was developed as part of my thesis research on KeePassXC security, which uses the KDBX format by default.

### References
For additional context and resources, I referenced the following:
- [KeePass Documentation on KDBX 4 Format](https://keepass.info/help/kb/kdbx_4.html)
- [KeepassDecrypt GitHub Repository](https://github.com/scubajorgen/KeepassDecrypt)
- [Documenting KeePass KDBX4 File Format](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/)

## Features
- Extracts outer headers from KDBX 4 files using Argon2 as the KDF.
- Converts extracted parameters into a format compatible with John the Ripper and Hashcat.

## Motivation
This script was primarily developed for research purposes, facilitating the analysis of the KDBX format and its security aspects.

I also created a similar script that, instead of converting the KDBX file to a specific format, reads and prints all the outer headers of the KDBX file. This script is compatible with all KDFs, as long as the file follows the KDBX 4 format. 

If you are interested it can be found in my other public repositories or in [KeePass2-kdbx-4-header-extract](https://github.com/CamposTaPro/KeePass2-kdbx-4-header-extract)!

## Compatibility
This script has been tested with a few databases using **Argon2** as the KDF.

If you encounter any issues, please [create an issue](#) in this repository, and I will address it as soon as possible.

## Usage
### Prerequisites
- Python 3 (any version should suffice)

### Running the Script
To extract the relevant parameters from a KDBX 4 file, run the following command:

```shell
python keepass2johnArgon2.py example.kdbx
```

To view usage instructions, use the `-h` flag:

```shell
python keepass2johnArgon2.py -h
```

#### Output Example
Here’s an example output when processing a KDBX database with Argon2d:

```shell
keepass2john$keepass$*4*42*ef636ddf*67108864*19*6*b929a7bc6ba6763c93082760f7afbe5413fd2da0f4fb6a71115a387af585012f*f7e118d4a45bb877dfa21131e0d27f1213cff5f6de540701f1d97aef52ab4783*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000b929a7bc6ba6763c93082760f7afbe5413fd2da0f4fb6a71115a387af585012f07100000008efcab5ab97f52626f197c4902aa8c170b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c050100000049080000002a0000000000000005010000004d080000000000000400000000040100000050040000000600000042010000005320000000f7e118d4a45bb877dfa21131e0d27f1213cff5f6de540701f1d97aef52ab478304010000005604000000130000000000040000000d0a0d0a*ee570c4fb35005be47deb222aed44362e733d26a92cccc67a3e5b42435d6586b
```

## Contributions
Contributions are welcome! If you have suggestions or improvements, feel free to submit a pull request or open an issue.
