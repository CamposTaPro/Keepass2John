import struct
import argparse

def main():
    parser = argparse.ArgumentParser(description="Read and parse a KDBX v4 file for Hashcat mode 34300.")
    parser.add_argument("filename", type=str, help="Path to the KDBX file to be read.")
    args = parser.parse_args()
    dbname = args.filename.split('.')[0]
    data, varientMapData = readFile(args.filename)
    print_values(data, varientMapData, dbname)

def read_fixed_size(file, size, unpack_format=None, hex_output=False):
    """Helper function to read data from the file."""
    data = file.read(size)
    if not data or len(data) != size:
        raise ValueError("Unexpected end of file or incomplete data read.")
    if unpack_format:
        return struct.unpack(unpack_format, data)[0]
    if hex_output:
        return data.hex()
    return data

def read_fixed_size_string(file, size):
    """Helper function to read a string from the file."""
    data = file.read(size)
    return data.decode("utf-8")

def read_varientMap(file):
    """Reads the VariantMap containing Argon2 parameters."""
    varientDictionaryFormat = read_fixed_size(file, 2, "<H")
    # Read KDF UUID
    _ = file.read(1)  # Type byte
    uuidKDFNameSize = read_fixed_size(file, 4, "<I")
    uuidKDFName = read_fixed_size_string(file, uuidKDFNameSize)
    uuidKDFValueSize = read_fixed_size(file, 4, "<I")
    uuidKDFValue = read_fixed_size(file, uuidKDFValueSize, None, True)
    if uuidKDFValue not in ["ef636ddf8c29444b91f7a9a403e30a0c", "9e298b1956db4773b23dfc3ec6f0a1e6"]:
        print("Error: The UUID of the KDF does not match Argon2d or Argon2id.")
        exit(1)

    # Read Iterations
    _ = file.read(1)
    argon2IterationNameSize = read_fixed_size(file, 4, "<I")
    argon2IterationName = read_fixed_size_string(file, argon2IterationNameSize)
    argon2IterationValueSize = read_fixed_size(file, 4, "<I")
    argon2IterationValue = read_fixed_size(file, argon2IterationValueSize, "<Q")

    # Read Memory
    _ = file.read(1)
    argon2MemoryNameSize = read_fixed_size(file, 4, "<I")
    argon2MemoryName = read_fixed_size_string(file, argon2MemoryNameSize)
    argon2MemoryValueSize = read_fixed_size(file, 4, "<I")
    argon2MemoryValue = read_fixed_size(file, argon2MemoryValueSize, "<Q")

    # Read Parallelism
    _ = file.read(1)
    argon2ParallelismNameSize = read_fixed_size(file, 4, "<I")
    argon2ParallelismName = read_fixed_size_string(file, argon2ParallelismNameSize)
    argon2ParallelismValueSize = read_fixed_size(file, 4, "<I")
    argon2ParallelismValue = read_fixed_size(file, argon2ParallelismValueSize, "<I")

    # Read Salt (Transformseed)
    _ = file.read(1)
    argon2SaltNameSize = read_fixed_size(file, 4, "<I")
    argon2SaltName = read_fixed_size_string(file, argon2SaltNameSize)
    argon2SaltValueSize = read_fixed_size(file, 4, "<I")
    argon2SaltValue = read_fixed_size(file, argon2SaltValueSize, None, True)

    # Read Version
    _ = file.read(1)
    argon2VersionNameSize = read_fixed_size(file, 4, "<I")
    argon2VersionName = read_fixed_size_string(file, argon2VersionNameSize)
    argon2VersionValueSize = read_fixed_size(file, 4, "<I")
    argon2VersionValue = read_fixed_size(file, argon2VersionValueSize, "<I")

    # Check for end of VariantMap
    checkEnd = read_fixed_size(file, 1, None, True)

    return {
        "uuidKDFValue": uuidKDFValue,
        "argon2IterationValue": argon2IterationValue,
        "argon2MemoryValue": argon2MemoryValue,
        "argon2ParallelismValue": argon2ParallelismValue,
        "argon2SaltValue": argon2SaltValue,
        "argon2VersionValue": argon2VersionValue,
    }

def readFile(path_file):
    """Reads the KDBX file and extracts necessary header information."""
    with open(str(path_file), "rb") as file:

        # Mark the beginning of the header content
        header_start_pos = file.tell()

        # Read Signatures
        signature1 = read_fixed_size(file, 4, "<I", True)
        signature2 = read_fixed_size(file, 4, "<I", True)

        # Read Version (must be v4 for Argon2)
        minor_version = read_fixed_size(file, 2, "<H")
        major_version = read_fixed_size(file, 2, "<H")
        if major_version != 4:
            print(f"Error: Unsupported KDBX version {major_version}.{minor_version}. This script only supports KDBX v4.")
            exit(1)
        version = f"{major_version}"


        # Read all header fields to determine the full header size
        CipherIDFlag = read_fixed_size(file, 1, "<B")
        CipherIDSize = read_fixed_size(file, 4, "<I")
        CipherID = read_fixed_size(file, CipherIDSize, None, True)
        
        compressionFlag = read_fixed_size(file, 1, "<B")
        compressionSize = read_fixed_size(file, 4, "<I")
        compression = read_fixed_size(file, compressionSize, "<I")
        
        saltFlag = read_fixed_size(file, 1, "<B")
        saltSize = read_fixed_size(file, 4, "<I")
        master_seed = read_fixed_size(file, saltSize, None, True)
        
        encryptionIVFlag = read_fixed_size(file, 1, "<B")
        encryptionIVSize = read_fixed_size(file, 4, "<I")
        encryptionIV = read_fixed_size(file, encryptionIVSize, None, True)
        
        kdfParamFlag = read_fixed_size(file, 1, "<B")
        kdfParamSize = read_fixed_size(file, 4, "<I")
        
        varientMapData = read_varientMap(file)
        
        headerEndFlag = read_fixed_size(file, 1, "<B")
        headerEndSize = read_fixed_size(file, 4, "<I")
        headerEnd = read_fixed_size(file, headerEndSize, None, True)
        
        # Mark the end of the header content
        header_end_pos = file.tell()
        
        # Go back, read the raw header bytes, and hex-encode them
        header_content_size = header_end_pos - header_start_pos
        file.seek(header_start_pos)
        #print(header_start_pos) 
        raw_header_hex = read_fixed_size(file, header_content_size, None, True)

        # The next 32 bytes are the SHA256 hash of the header (not needed for hash format)
        _ = read_fixed_size(file, 32, None, True)
        # The final 32 bytes are the HMAC-SHA256 of the header, which is our target hash
        headerHMACSha256 = read_fixed_size(file, 32, None, True)

    data = {
        "version": version,
        "master_seed": master_seed,
        "raw_header_hex": raw_header_hex,
        "headerHMACSha256": headerHMACSha256
    }
    return data, varientMapData

def print_values(data, vmdata, dbname):
    """Formats and prints the hash string correctly for Hashcat mode 34300."""
    
    # The KDF UUID for the hashcat format is the first 8 characters of the full hex UUID
    kdf_uuid = vmdata['uuidKDFValue'][:8]

    # Format the final hash string according to the module specification.
    # $keepass$*<ver>*<iter>*<kdf_uuid>*<mem>*<ver>*<para>*<masterseed>*<transformseed>*<header>*<headerhmac>
    print(
        "{:s}:$keepass$*{:s}*{:d}*{:s}*{:d}*{:d}*{:d}*{:s}*{:s}*{:s}*{:s}".format(
            dbname,                         # Filename (used as username)
            data['version'],                # 1. KeePass DB version (e.g., 4)
            vmdata['argon2IterationValue'], # 2. Iterations
            kdf_uuid,                       # 3. KDF UUID (e.g., ef636ddf)
            vmdata['argon2MemoryValue'],    # 4. Memory usage in bytes
            vmdata['argon2VersionValue'],   # 5. Argon2 version (e.g., 19)
            vmdata['argon2ParallelismValue'],# 6. Parallelism
            data['master_seed'],            # 7. Masterseed
            vmdata['argon2SaltValue'],      # 8. Transformseed (the Argon2 salt)
            data['raw_header_hex'],         # 9. Full raw header, hex-encoded
            data['headerHMACSha256']        # 10. Header HMAC (the target hash/digest)
        )
    )

if __name__ == "__main__":
    main()