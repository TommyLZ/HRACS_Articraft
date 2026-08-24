#include "PublicParam.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/eax.h>
#include <cryptopp/files.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;
namespace fs = std::filesystem;

pairing_t pairing;
element_t g, h;

void sysInitial()
{
    cout << "*********************************System Initialization********************************" << endl;
    char param[4096];
    size_t count = 0;

    const fs::path param_path = "../Param/a.param";
    ifstream param_file(param_path, ios::binary);
    if (param_file)
    {
        param_file.read(param, sizeof(param));
        count = static_cast<size_t>(param_file.gcount());
    }
    else
    {
        count = fread(param, 1, sizeof(param), stdin);
    }

    if (!count)
        pbc_die("input error");

    pairing_init_set_buf(pairing, param, count);

    element_init_G1(h, pairing);
    element_init_G2(g, pairing);

    element_random(g);

    cout << "System initialization finished!" << endl;
}

Integer randomGeneration(const int &secureParam)
{
    AutoSeededRandomPool prng;
    SecByteBlock randomBlock(secureParam / 8);
    prng.GenerateBlock(randomBlock, randomBlock.size());

    Integer randomInt(randomBlock, randomBlock.size());

    if (randomInt.BitCount() < 128)
    {
        randomInt <<= (128 - randomInt.BitCount());
    }

    return randomInt;
}

string Integer_to_string(const Integer &integer)
{
    string str;
    stringstream ss;

    ss << hex << integer;
    ss >> str;
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    str = str.substr(0, str.size() - 1);

    return str;
}

string sha256Hash(string &str)
{
    string value;
    SHA256 sha256;

    StringSource ss(
        str,
        true,
        new HashFilter(sha256, new HexEncoder(new CryptoPP::StringSink(value))));
    return value;
}

void writeToBin(ofstream &outFile, string str)
{
    int strLength = str.length();
    outFile.write(reinterpret_cast<char *>(&strLength), sizeof(int));
    outFile.write(str.c_str(), strLength);
}

void readFromBin(ifstream &inFile, string &str)
{
    int strLength;
    inFile.read(reinterpret_cast<char *>(&strLength), sizeof(int));
    char *str_char = new char[strLength + 1];
    inFile.read(str_char, strLength);
    str_char[strLength] = '\0';
    str = str_char;
}

Integer string_To_Integer(string &str)
{
    char *a = new char[200];
    int i = 0;

    for (; i < str.size(); ++i)
    {
        a[i] = str[i];
    }

    a[i++] = 'h';
    a[i] = '\0';

    Integer H(a);

    return H;
}

void KDF(string &key, string &psw, string &salt, CryptoPP::byte *derivedKey)
{
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(derivedKey, 16, 0, (CryptoPP::byte *)psw.data(), psw.size(), (CryptoPP::byte *)salt.data(), salt.size(), 10000);
    HexEncoder hex(new StringSink(key));
    hex.Put(derivedKey, 16);
    hex.MessageEnd();
}

void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher)
{

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, 16, iv);
    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new Base64Encoder(
                                                    new StringSink(cipher),
                                                    false)));
}

void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain)
{

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(cipher, true,
                 new Base64Decoder(
                     new StreamTransformationFilter(decryption,
                                                    new StringSink(plain))));
}

void aes_EAX_FileEnc(const std::string &infilename,
                     const CryptoPP::byte *key,
                     const CryptoPP::byte *iv,
                     const std::string &outfilename)
{
    std::ifstream input(infilename, std::ios::binary);
    if (!input.is_open())
    {
        std::cerr << "Error opening file for reading: " << infilename << std::endl;
        return;
    }

    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, 16, iv, 16);

    AuthenticatedEncryptionFilter ef(enc, new FileSink(outfilename.c_str()));

    const size_t bufferSize = 8192;
    CryptoPP::byte buffer[bufferSize];

    while (input)
    {
        input.read(reinterpret_cast<char *>(buffer), bufferSize);
        std::streamsize bytesRead = input.gcount();
        if (bytesRead > 0)
            ef.Put(buffer, static_cast<size_t>(bytesRead));
    }

    ef.MessageEnd();
    input.close();

    std::cout << "Encrypted: " << infilename << " -> " << outfilename << std::endl;
}

void aes_EAX_FileDec(const std::string &infilename,
                     const CryptoPP::byte *key,
                     const CryptoPP::byte *iv,
                     const std::string &outfilename)
{

    ifstream input(infilename, ios::binary);
    if (!input.is_open())
    {
        cerr << "Error opening file for reading: " << infilename << endl;
        return;
    }

    EAX<AES>::Decryption dec;
    dec.SetKeyWithIV(key, 16, iv, 16);

    AuthenticatedDecryptionFilter df(dec, new FileSink(outfilename.c_str()));

    const size_t bufferSize = 8192;
    CryptoPP::byte buffer[bufferSize];

    while (input)
    {
        input.read(reinterpret_cast<char *>(buffer), bufferSize);
        std::streamsize bytesRead = input.gcount();
        if (bytesRead > 0)
            df.Put(buffer, static_cast<size_t>(bytesRead));
    }

    df.MessageEnd();
    input.close();

    if (!df.GetLastResult())
    {
        cerr << "❌ Authentication failed for file: " << infilename << endl;
        return;
    }

    cout << "Decrypted: " << infilename << " -> " << outfilename << endl;
}
