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

Integer randomGeneration(const int &secureParam);

string sha256Hash(string &str);

void writeToBin(ofstream &outFile, string str);

void readFromBin(ifstream &inFile, string &str);

string Integer_to_string(const Integer &integer);

string elementToString(element_t &element);

void save_to_file(element_t key, const char *filename);

void load_from_file(element_t key, const char *filename);

void verify(element_t &beta, element_t &alpha, element_t &public_key);

void save_State(const Integer &nr, const string &filename);

Integer load_State(const string &filename);

void aes_EAX_FileEnc(const string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const string &outfilename);

void aes_EAX_FileDec(const std::string &infilename, const CryptoPP::byte *key, const CryptoPP::byte *iv, const std::string &outfilename);

double getClientTime();