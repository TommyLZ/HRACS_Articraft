#pragma once

#include <cryptopp/integer.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

const int secureParam = 128;

static double client_running_time = 0.0;
static double cloud_running_time = 0.0;
static double key_running_time = 0.0;

void sysInitial();

string hex_encode(const unsigned char *buffer, int length);

string sha256Hash(string &str);

Integer randomGeneration(const int &secureParam);

string Integer_to_string(const Integer &integer);

Integer string_To_Integer(string &Integer);

void integer_To_Bytes(Integer num, CryptoPP::byte *bytes);

void writeToBin(ofstream &outFile, string str);

void readFromBin(ifstream &inFile, string &str);

void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher);

void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain);

void authentication(string &ID_u_str, string &cred, string &EM, CryptoPP::byte *iv);

void aes_EAX_FileEnc(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);

void aes_EAX_FileDec(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);

bool encryptFileToSingleBlob(const std::string &mk,
                             const std::string &inputPath,
                             const std::string &cipherPath);