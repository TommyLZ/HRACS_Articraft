#include "PublicParam.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/eax.h>
#include <cryptopp/files.h>
#include <pbc/pbc.h>
using namespace std;

pairing_t pairing;
element_t g, h;

void sysInitial()
{

    char param[1024];
    FILE *param_file = fopen("../Param/a.param", "rb");
    if (!param_file)
        param_file = fopen("Param/a.param", "rb");
    if (!param_file)
        pbc_die("input error: cannot open Param/a.param");

    size_t count = fread(param, 1, 1024, param_file);
    fclose(param_file);
    if (!count)
        pbc_die("input error");

    pairing_init_set_buf(pairing, param, count);

    element_init_G1(h, pairing);
    element_init_G1(g, pairing);

    element_random(g);
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

string elementToString(element_t &element)
{
    size_t elementSize = element_length_in_bytes_compressed(element);
    unsigned char *elementBytes = new unsigned char[elementSize];
    element_to_bytes_compressed(elementBytes, element);

    std::ostringstream oss;
    for (size_t i = 0; i < elementSize; i++)
    {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(elementBytes[i]);
    }

    delete[] elementBytes;

    return oss.str();
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

void save_to_file(element_t key, const char *filename)
{
    std::ofstream outfile(filename, std::ios::binary);
    size_t key_size = element_length_in_bytes(key);
    unsigned char key_bytes[key_size];
    element_to_bytes(key_bytes, key);
    outfile.write((char *)key_bytes, key_size);
    outfile.close();
}

void load_from_file(element_t key, const char *filename)
{
    std::ifstream infile(filename, std::ios::binary);
    infile.seekg(0, infile.end);
    size_t key_size = infile.tellg();
    infile.seekg(0, infile.beg);
    unsigned char key_bytes[key_size];
    infile.read((char *)key_bytes, key_size);
    element_from_bytes(key, key_bytes);
    infile.close();
}

void verify(element_t &beta, element_t &alpha, element_t &public_key)
{
    element_t tmp1;
    element_t tmp2;

    element_init_GT(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    pairing_apply(tmp1, beta, g, pairing);
    pairing_apply(tmp2, alpha, public_key, pairing);

    if (!element_cmp(tmp1, tmp2))
    {
    }
    else
    {
        return;
    }
}

void save_State(const Integer &nr, const string &filename)
{
    ofstream file(filename, std::ios::binary);
    if (file)
    {
        vector<CryptoPP::byte> encoded(nr.MinEncodedSize());
        nr.Encode(encoded.data(), encoded.size());
        file.write(reinterpret_cast<const char *>(&encoded[0]), encoded.size());
    }
    file.close();
}

Integer load_State(const string &filename)
{
    ifstream file(filename, ios::binary);
    if (file)
    {
        file.seekg(0, ios::end);
        streampos length = file.tellg();
        file.seekg(0, ios::beg);

        vector<CryptoPP::byte> encoded(length);
        file.read(reinterpret_cast<char *>(&encoded[0]), length);

        CryptoPP::Integer nr;
        nr.Decode(encoded.data(), encoded.size());
        file.close();
        return nr;
    }
    else
    {
        throw runtime_error("Failed to open file: " + filename);
    }
}

static std::string bytes_to_hex(const CryptoPP::byte *data, size_t len)
{
    static const char hexmap[] = "0123456789ABCDEF";
    std::string s(len * 2, ' ');
    for (size_t i = 0; i < len; ++i)
    {
        s[2 * i] = hexmap[(data[i] >> 4) & 0xF];
        s[2 * i + 1] = hexmap[data[i] & 0xF];
    }
    return s;
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

    AuthenticatedEncryptionFilter ef(
        enc,
        new FileSink(outfilename.c_str()));

    const size_t bufferSize = 8192;
    CryptoPP::byte buffer[bufferSize];

    while (input)
    {
        input.read(reinterpret_cast<char *>(buffer), bufferSize);
        auto bytesRead = input.gcount();
        if (bytesRead > 0)
            ef.Put(buffer, static_cast<size_t>(bytesRead));
    }

    ef.MessageEnd();
    input.close();
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
        auto bytesRead = input.gcount();
        if (bytesRead > 0)
            df.Put(buffer, static_cast<size_t>(bytesRead));
    }

    df.MessageEnd();
    input.close();

    if (!df.GetLastResult())
    {
        cerr << "Authentication failed for file: " << infilename << endl;
        return;
    }
}

double getClientTime()
{
    return client_running_time;
}
