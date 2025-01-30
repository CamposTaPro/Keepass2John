# KeePass2 to John the Ripper Converter

## Introduction
This script extracts the outer headers of a KDBX 4 file and formats the relevant parameters into a structure compatible with John the Ripper (JtR) password cracker.

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
- Converts extracted parameters into a format compatible with John the Ripper.

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
Passwords:$keepass$*4*58*ef636ddf8c29444b91f7a9a403e30a0c*16777216*19*2*470541af0812fa595728152e0fae91e785ab8887bc954b5cd64f276587ba8fad*48148e2966c90461318ccb5907ae10602ffabbfd6b5744963ae8ab3bd9c68c2d*68004a9e9190199b5269fdfe2bd986388cecc65d60feccee9874be7ede84025d*357a360ee25b582e0b2ded6e815fc95838e3187240b3ed7a2b3831020e4834d1
```

## Contributions
Contributions are welcome! If you have suggestions or improvements, feel free to submit a pull request or open an issue.
