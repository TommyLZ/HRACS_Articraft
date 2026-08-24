#include <iostream>
#include <cryptopp/pwdbased.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/ccm.h>
using namespace std;
using namespace CryptoPP;

const int secureParam = 128;

static double client_running_time = 0.0;
static double cloud_running_time = 0.0;
static double key_running_time = 0.0;

void sysInitial();

Integer randomGeneration(const int &secureParam);

string Integer_to_string(const Integer &integer);

string sha256Hash(string &str);

void writeToBin(ofstream &outFile, string str);

void readFromBin(ifstream &inFile, string &str);

Integer string_To_Integer(string &str);

void KDF(string &key, string &psw, string &salt, CryptoPP::byte *derivedKey);

void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher);

void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain);

void aes_EAX_FileEnc(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);

void aes_EAX_FileDec(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);