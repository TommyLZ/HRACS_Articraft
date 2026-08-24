#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <pbc/pbc.h>
using namespace std;
using namespace CryptoPP;

extern pairing_t pairing;
extern double cloud_running_time;

static bool secret_key_generated = false;

CloudServer::CloudServer()
{
    auto start = chrono::high_resolution_clock::now();

    element_init_Zr(this->secret_key, pairing);

    if (!secret_key_generated)
    {

        element_random(this->secret_key);
        this->ns = randomGeneration(secureParam);

        save_to_file(this->secret_key, "../Store/cs_secret_key.bin");
        save_State(this->ns, "../Store/cs_state.bin");

        secret_key_generated = true;
    }
    else
    {
        load_from_file(this->secret_key, "../Store/cs_secret_key.bin");
        this->ns = load_State("../Store/cs_state.bin");
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::store(string &id, string &cred_cs)
{
    auto start = chrono::high_resolution_clock::now();

    string filename = "../Store/Cred_cs.bin";

    ifstream fileCheck(filename);
    bool fileExists = fileCheck.good();
    fileCheck.close();

    if (fileExists)
    {

        std::ofstream clearFile(filename, ios::trunc);
        clearFile.close();
    }

    ofstream outFile(filename, ios::binary | ios::app);

    if (!outFile.is_open())
    {
        cout << "Error opening file for writing." << endl;
    }

    writeToBin(outFile, id);
    writeToBin(outFile, cred_cs);

    outFile.close();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::authenInEnc(string &id, string &cred_cs)
{
    auto start = chrono::high_resolution_clock::now();

    string filename = "../Store/Cred_cs.bin";
    ifstream inFile(filename, ios::binary);

    if (!inFile.is_open())
    {
        cout << "Error opening file for reading." << endl;
    }

    readFromBin(inFile, id);
    string cred_CS;
    readFromBin(inFile, cred_CS);

    inFile.close();

    if (cred_CS != cred_cs)
    {
        cout << "The cloud server authentication fails!" << endl;
        return;
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::encrypt(Integer nr, element_t &c0, element_t &c1, element_t &public_key, string &cred_cs)
{
    auto start = chrono::high_resolution_clock::now();

    string input0_str = Integer_to_string(nr) + "0";
    char *input0 = new char[input0_str.size() + 1];
    strcpy(input0, input0_str.c_str());

    string input1_str = Integer_to_string(nr) + "1";
    char *input1 = new char[input1_str.size() + 1];
    strcpy(input1, input1_str.c_str());

    element_t hr0;
    element_init_G1(hr0, pairing);
    element_t hr1;
    element_init_G1(hr1, pairing);
    element_from_hash(hr0, input0, strlen(input0));
    element_from_hash(hr1, input1, strlen(input1));

    verify(c0, hr0, public_key);
    verify(c1, hr1, public_key);

    string input0_str0 = cred_cs + Integer_to_string(this->ns) + "0";
    char *input00 = new char[input0_str0.size() + 1];
    strcpy(input00, input0_str0.c_str());

    string input1_str1 = cred_cs + Integer_to_string(this->ns) + "1";
    char *input11 = new char[input1_str1.size() + 1];
    strcpy(input11, input1_str1.c_str());

    element_t hs0;
    element_init_G1(hs0, pairing);
    element_t hs1;
    element_init_G1(hs1, pairing);
    element_from_hash(hs0, input00, strlen(input00));
    element_from_hash(hs1, input11, strlen(input11));

    element_t tmp1, tmp2, tmp3, tmp4, t0, t1, mk;
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_G1(tmp4, pairing);
    element_init_G1(t0, pairing);
    element_init_G1(t1, pairing);
    element_init_G1(mk, pairing);

    element_random(mk);

    element_pow_zn(tmp1, hs0, this->secret_key);
    element_mul(t0, c0, tmp1);

    element_pow_zn(tmp2, hs1, this->secret_key);
    element_pow_zn(tmp3, mk, this->secret_key);

    element_mul(tmp4, tmp2, tmp3);

    element_mul(t1, c1, tmp4);

    save_to_file(t0, "../Store/cipher0.bin");
    save_to_file(t1, "../Store/cipher1.bin");

    delete[] input0;
    delete[] input1;
    delete[] input00;
    delete[] input11;

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::decrypt(element_t &c0, string &cred_cs, element_t &hr1, element_t &hs1)
{
    auto start = chrono::high_resolution_clock::now();

    Integer nr = load_State("../Store/ks_state.bin");

    string input0_str = Integer_to_string(nr) + "0";
    char *input0 = new char[input0_str.size() + 1];
    strcpy(input0, input0_str.c_str());

    string input1_str = Integer_to_string(nr) + "1";
    char *input1 = new char[input1_str.size() + 1];
    strcpy(input1, input1_str.c_str());

    element_t hr0;
    element_init_G1(hr0, pairing);
    element_from_hash(hr0, input0, strlen(input0));

    element_from_hash(hr1, input1, strlen(input1));

    string input0_str0 = cred_cs + Integer_to_string(this->ns) + "0";
    char *input00 = new char[input0_str0.size() + 1];
    strcpy(input00, input0_str0.c_str());

    string input1_str1 = cred_cs + Integer_to_string(this->ns) + "1";
    char *input11 = new char[input1_str1.size() + 1];
    strcpy(input11, input1_str1.c_str());

    element_t hs0;
    element_init_G1(hs0, pairing);

    element_from_hash(hs0, input00, strlen(input00));
    element_from_hash(hs1, input11, strlen(input11));

    element_t invert, tmp1, t0, t1, mk;
    element_init_Zr(invert, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(t0, pairing);

    load_from_file(t0, "../Store/cipher0.bin");
    element_pow_zn(tmp1, hs0, this->secret_key);
    element_div(c0, t0, tmp1);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::key_Recover(element_t &mk, element_t &c1, element_t &hr1, element_t &hs1, element_t &public_key)
{
    auto start = chrono::high_resolution_clock::now();

    verify(c1, hr1, public_key);

    element_t tmp1, tmp2, tmp3, inverse, t1;
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_G1(t1, pairing);
    element_init_Zr(inverse, pairing);

    load_from_file(t1, "../Store/cipher1.bin");

    element_div(tmp1, t1, c1);

    element_pow_zn(tmp2, hs1, this->secret_key);
    element_div(tmp3, tmp1, tmp2);

    element_invert(inverse, this->secret_key);

    element_pow_zn(mk, tmp3, inverse);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cloud_running_time += duration.count();
}

void CloudServer::dataEncryption(element_t &mk, CryptoPP::byte *iv)
{
    string infilename = "../Store/data.txt";
    string outfilename = "../Store/encryption.bin";

    string mk_str = elementToString(mk);

    CryptoPP::byte aes_key[16];
    StringSource(mk_str, true, new HexDecoder(new ArraySink(aes_key, 16)));

    aes_EAX_FileEnc(infilename, aes_key, iv, outfilename);
}

void CloudServer::dataDecryption(element_t &mk, CryptoPP::byte *iv)
{
    string infilename = "../Store/encryption.bin";
    string outfilename = "../Store/decryption.txt";

    string mk_str = elementToString(mk);

    CryptoPP::byte aes_key[16];
    StringSource(mk_str, true, new HexDecoder(new ArraySink(aes_key, 16)));

    aes_EAX_FileDec(infilename, aes_key, iv, outfilename);
}

void CloudServer::fileEncryption(element_t &mk,
                                 CryptoPP::byte *iv,
                                 string infilename,
                                 string outfilename,
                                 string ivpath)
{

    std::string mk_str = elementToString(mk);

    CryptoPP::byte aes_key[16];
    if (mk_str.size() >= 16)
        memcpy(aes_key, mk_str.data(), 16);
    else
    {
        std::cerr << "Error: master key too short (" << mk_str.size() << " bytes)\n";
        return;
    }

    {
        std::ofstream ivFile(ivpath, std::ios::binary);
        if (!ivFile.is_open())
        {
            std::cerr << "Error: cannot open IV file for writing: " << ivpath << std::endl;
            return;
        }

        ivFile.write(reinterpret_cast<const char *>(iv), 16);
        ivFile.close();
    }

    std::ofstream test(outfilename);
    if (!test.is_open())
    {
        std::cerr << "Error: cannot open output file: " << outfilename << std::endl;
        return;
    }
    test.close();

    aes_EAX_FileEnc(infilename, aes_key, iv, outfilename);
}

void CloudServer::fileDecryption(element_t &mk, CryptoPP::byte *iv, string infilename, string outfilename)
{

    string mk_str = elementToString(mk);

    CryptoPP::byte aes_key[16];
    if (mk_str.size() >= 16)
        memcpy(aes_key, mk_str.data(), 16);
    else
    {
        std::cerr << "Error: master key too short (" << mk_str.size() << " bytes)\n";
        return;
    }

    aes_EAX_FileDec(infilename, aes_key, iv, outfilename);
}
