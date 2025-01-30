import struct
import argparse

def bytes_to_mib(byte_value):
    return byte_value / (1024 * 1024)  # Divide by 2^20 (1,048,576)

def main():
    parser = argparse.ArgumentParser(description="Read and parse a KDBX file.")
    parser.add_argument("filename", type=str, help="Path to the KDBX file to be read.")
    args = parser.parse_args()
    dbname= args.filename.split('.')[0]
    data, varientMapData=readFile(args.filename)
    print_values(data,varientMapData,dbname)

def read_fixed_size(file, size, unpack_format=None, hex_output=False):
    data = file.read(size)
    if unpack_format:
        return struct.unpack(unpack_format, data)[0]
    if hex_output:
        return data.hex()
    return data

def read_fixed_size_string(file,size):
    data = file.read(size)
    return data.decode("utf-8")

def read_varientMap(file):

    varientDictionaryFormat=read_fixed_size(file,2,"<H")
    uuidKDFType= file.read(1) # not used for printing but it still needs to be read
    uuidKDFNameSize=read_fixed_size(file,4,"<I")
    uuidKDFName=read_fixed_size_string(file,uuidKDFNameSize)
    uuidKDFValueSize=read_fixed_size(file,4,"<I")
    uuidKDFValue=read_fixed_size(file,uuidKDFValueSize,None,True)
    if uuidKDFValue not in ["ef636ddf8c29444b91f7a9a403e30a0c","9e298b1956db4773b23dfc3ec6f0a1e6"]:
        print("Error:The UUID of the KDF does not match the one for Argon2d or Argon2id")
        exit(1)
    ######## For entry I (Iterations)  ##################
    argon2IterationType= file.read(1)
    argon2IterationNameSize=read_fixed_size(file,4,"<I")
    argon2IterationName=read_fixed_size_string(file,argon2IterationNameSize)
    argon2IterationValueSize=read_fixed_size(file,4,"<I")
    argon2IterationValue=read_fixed_size(file,argon2IterationValueSize,"<Q")
    ######## For entry M (Memory)  ##################
    argon2MemoryType= file.read(1)
    argon2MemoryNameSize=read_fixed_size(file,4,"<I")
    argon2MemoryName=read_fixed_size_string(file,argon2MemoryNameSize)
    argon2MemoryValueSize=read_fixed_size(file,4,"<I")
    argon2MemoryValue=read_fixed_size(file,argon2MemoryValueSize,"<Q")
    ######## For entry P (Parallelism)  ##################
    argon2ParallelismTypeByte= file.read(1)
    argon2ParallelismNameSize=read_fixed_size(file,4,"<I")
    argon2ParallelismName=read_fixed_size_string(file,argon2ParallelismNameSize)
    argon2ParallelismValueSize=read_fixed_size(file,4,"<I")
    argon2ParallelismValue=read_fixed_size(file,argon2ParallelismValueSize,"<I")
    ######## For entry S (Salt)  ##################
    argon2SaltTypeByte= file.read(1)
    argon2SaltNameSize=read_fixed_size(file,4,"<I")
    argon2SaltName=read_fixed_size_string(file,argon2SaltNameSize)
    argon2SaltValueSize=read_fixed_size(file,4,"<I")
    argon2SaltValue=read_fixed_size(file,argon2SaltValueSize,None,True)
    ######## For entry V (Version)  ##################
    argon2VersionTypeByte= file.read(1)
    argon2VersionNameSize=read_fixed_size(file,4,"<I")
    argon2VersionName=read_fixed_size_string(file,argon2VersionNameSize)
    argon2VersionValueSize=read_fixed_size(file,4,"<I")
    argon2VersionValue=read_fixed_size(file,argon2VersionValueSize,"<I",True)
    ######## Check for end of VariantMap ##################
    checkEnd=read_fixed_size(file,1,None,True)
    data={
        "varientDictionaryFormat": hex(varientDictionaryFormat),
        "uuidKDFValueSize":uuidKDFValueSize,
        "uuidKDFName":uuidKDFName,
        "uuidKDFValueSize":uuidKDFValueSize,
        "uuidKDFValue":uuidKDFValue,
        "argon2IterationValueSize":argon2IterationValueSize,
        "argon2IterationName":argon2IterationName,
        "argon2IterationValue":argon2IterationValue,
        "argon2MemoryValueSize":argon2MemoryValueSize,
        "argon2MemoryName":argon2MemoryName,
        "argon2MemoryValue":argon2MemoryValue,
        "argon2ParallelismValueSize":argon2ParallelismValueSize,
        "argon2ParallelismName":argon2ParallelismName,
        "argon2ParallelismValue":argon2ParallelismValue,
        "argon2SaltValueSize":argon2SaltValueSize,
        "argon2SaltName":argon2SaltName,
        "argon2SaltValue":argon2SaltValue,
        "argon2VersionValueSize":argon2VersionValueSize,
        "argon2VersionName":argon2VersionName,
        "argon2VersionValue":hex(argon2VersionValue),
        "checkEnd":checkEnd}
    return data




def readFile(path_file):
    with open(str(path_file), "rb") as file: #teste123.kdbx - AES  Passwords.kdbx- argon2d
        ######## Read Signtures ##################
        signature1=read_fixed_size(file,4,"<I")
        signature2=read_fixed_size(file,4,"<I")
        signature={
            "signature1":hex(signature1),
            "signature2":hex(signature2)
        }
        ######## Read Version of the kdbx file ##################
        minor_version = read_fixed_size(file, 2, "<H")
        major_version = read_fixed_size(file, 2, "<H")
        version = f"{major_version}"

        ######## Read the ID of the algorithm used to cipher ##################
        CipherIDFlag=read_fixed_size(file,1,"<B")
        CipherIDSize=read_fixed_size(file,4,"<I")
        CipherID=read_fixed_size(file,CipherIDSize,None,True)# important usar o .hex() quando so quero extrair o valor hexadecimal
        cipher={
            "CipherIDFlag":CipherIDFlag,
            "CipherIDSize": CipherIDSize,
            "CipherID": CipherID
        }
        ######## Read the compression algorithm used ##################
        compressionFlag=read_fixed_size(file,1,"<B")
        compressionSize=read_fixed_size(file,4,"<I")
        compression=read_fixed_size(file,compressionSize,"<I")
        compressionAlgorithm={
            "compressionFlag":compressionFlag,
            "compressionSize":compressionSize,
            "compression":compression
        }
        ######## Read the salt used for computing the keys ##################
        saltFlag=read_fixed_size(file,1,"<B")
        saltSize=read_fixed_size(file,4,"<I")
        salt=read_fixed_size(file,saltSize,None,True)
        saltData={
            "saltFlag":saltFlag,
            "saltSize":saltSize,
            "salt":salt
        }
        ######## Read the initialization vector for the encryption algorithm. ##################
        encryptionIVFlag=read_fixed_size(file,1,"<B")
        encryptionIVSize=read_fixed_size(file,4,"<I")
        encryptionIV=read_fixed_size(file,encryptionIVSize,None,True)# means the encryption algorithm is AES meaning this field is 16 bytes long
        encryptionInitializationVector={
            "encryptionIVFlag":encryptionIVFlag,
            "encryptionIVSize":encryptionIVSize,
            "encryptionIV":encryptionIV
        }
        ######## Read the parameters for the key derivation function (KDF) ##################
        kdfParamFlag=read_fixed_size(file,1,"<B")
        kdfParamSize=read_fixed_size(file,4,"<I")
        kdfParameters={
            "kdfParamFlag":kdfParamFlag,
            "kdfParamSize":kdfParamSize
        }
       # print(kdfParameters)
        ######## Read the varient map field ##################
        varientMapData=read_varientMap(file)
        ######## Check for end of Headers ##################
        headerEndFlag=read_fixed_size(file,1,"<B")
        headerEndSize=read_fixed_size(file,4,"<I")
        headerEnd=read_fixed_size(file,headerEndSize,None,True) # estava fazer unpack ao bytes mas como so queria comparar o valor hex nao era preciso fazer nada
        headerHashSha256=read_fixed_size(file,32,None,True)
        #print(headerHashSha256)
        headerHMACSha256=read_fixed_size(file,32,None,True)
        #print(headerHMACSha256)
    data={
        "signature":signature,
        "version":version,
        "cipher":cipher,
        "compressionAlgorithm":compressionAlgorithm,
        "saltData":saltData,
        "encryptionInitializationVector":encryptionInitializationVector,
        "kdfParameters":kdfParameters,
        "headerEndFlag":headerEndFlag,
        "headerEndSize":headerEndSize,
        "headerEnd":headerEnd,
        "headerHashSha256":headerHashSha256,
        "headerHMACSha256":headerHMACSha256
    }
    return data, varientMapData

def print_values(data,vmdata,dbname):

    #TODO implementar casos de erros 
    #codigo  com base em https://github.com/openwall/john/blob/bleeding-jumbo/src/keepass2john.c#L263
    print("{:s}:$keepass$*{:d}*{:d}*{:08x}*{:d}*{:d}*{:d}*{:s}*{:s}*{:s}*{:s}".format(dbname,int(data['version']),vmdata['argon2IterationValue'],int(vmdata['uuidKDFValue'],16),vmdata['argon2MemoryValue'],int(vmdata['argon2VersionValue'],0),vmdata['argon2ParallelismValue'],data['saltData']['salt'],vmdata['argon2SaltValue'],data['headerHashSha256'],data['headerHMACSha256']));
    # print_hex(header, content_size);
    # print("*");
    # print_hex(header_hmac, 32);

if __name__ == "__main__":
    main()
