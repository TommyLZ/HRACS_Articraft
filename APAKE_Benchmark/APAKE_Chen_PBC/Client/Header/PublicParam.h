#pragma once

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <openssl/evp.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
#include <openssl/sha.h>

using namespace std;
namespace fs = std::filesystem;

const char *SDH_PARAM_FILE = "../Key";
static const char *KEY_DIR = "../Key/gamma.dat";
const char *GEN_DIR = "../Key/g.dat";

static const int SALT_LEN = 16;
static const int PBKDF2_ITERS = 1000;
static const int BURN_ROUNDS = 40000;

pairing_t pairing;
element_t g, h;

void sysInitial()
{
    cout << "*********************************System Initialization********************************" << endl;

    ifstream input("../Param/a.param", ios::binary);
    if (!input)
        pbc_die("cannot open ../Param/a.param");
    vector<char> param((istreambuf_iterator<char>(input)), istreambuf_iterator<char>());
    if (param.empty())
        pbc_die("empty pairing parameter file: ../Param/a.param");

    pairing_init_set_buf(pairing, param.data(), param.size());

    element_init_G1(h, pairing);
    element_init_G1(g, pairing);

    element_random(g);

    cout << "System initialization finished!" << endl;
}

bool file_exists(const char *path)
{
    return fs::exists(path);
}

void ensure_key_dir()
{
    fs::path p(KEY_DIR);
    if (!fs::exists(p))
        fs::create_directories(p);
}

bool write_file(const string &path, const vector<unsigned char> &buf)
{
    ofstream ofs(path, ios::binary);
    if (!ofs)
        return false;
    ofs.write((const char *)buf.data(), buf.size());
    return true;
}

vector<unsigned char> read_file_vec(const string &path)
{
    ifstream ifs(path, ios::binary);
    if (!ifs)
        return {};
    return vector<unsigned char>((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
}

bool pbc_sdh_keygen(pairing_t pairing, element_t &gamma, element_t &W)
{

    element_init_Zr(gamma, pairing);
    element_random(gamma);

    element_init_G1(W, pairing);
    element_t G;
    element_init_G1(G, pairing);
    element_random(G);
    element_mul_zn(W, G, gamma);

    element_clear(G);
    return true;
}

vector<unsigned char> element_to_bytes_vec(element_t e)
{
    int len = element_length_in_bytes_compressed(e);
    vector<unsigned char> buf(len);
    element_to_bytes_compressed(buf.data(), e);
    return buf;
}

bool element_from_bytes_vec(element_t e, vector<unsigned char> &buf)
{
    return element_from_bytes_compressed(e, buf.data()) == 0;
}

std::vector<unsigned char> sha256_vec(const std::vector<unsigned char> &data)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    std::vector<unsigned char> out(32);

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("EVP_DigestInit_ex failed");

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
        throw std::runtime_error("EVP_DigestUpdate failed");

    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, out.data(), &out_len) != 1)
        throw std::runtime_error("EVP_DigestFinal_ex failed");

    EVP_MD_CTX_free(ctx);

    out.resize(out_len);
    return out;
}

vector<unsigned char> derive_session_key_H2(
    const vector<unsigned char> &Y_bytes,
    const vector<unsigned char> &sigmaS,
    const vector<unsigned char> &X_bytes,
    const vector<unsigned char> &sigmaC,
    element_t shared_point)
{
    vector<unsigned char> data;
    data.insert(data.end(), Y_bytes.begin(), Y_bytes.end());
    data.insert(data.end(), sigmaS.begin(), sigmaS.end());
    data.insert(data.end(), X_bytes.begin(), X_bytes.end());
    data.insert(data.end(), sigmaC.begin(), sigmaC.end());

    vector<unsigned char> S_bytes = element_to_bytes_vec(shared_point);
    data.insert(data.end(), S_bytes.begin(), S_bytes.end());

    return sha256_vec(data);
}

void save_elements(const std::string &filename, element_t arr[], int N)
{
    std::ofstream out(filename, std::ios::binary);
    if (!out.is_open())
    {
        std::cerr << "Cannot open file for writing\n";
        return;
    }

    for (int i = 0; i < N; i++)
    {
        int len = element_length_in_bytes_compressed(arr[i]);
        std::vector<unsigned char> buf(len);
        element_to_bytes_compressed(buf.data(), arr[i]);

        out.write((char *)&len, sizeof(int));

        out.write((char *)buf.data(), len);
    }
}

void load_elements(const std::string &filename, element_t arr[], int N, pairing_t pairing)
{
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open())
    {
        std::cerr << "Cannot open file for reading\n";
        return;
    }

    for (int i = 0; i < N; i++)
    {
        int len;
        in.read((char *)&len, sizeof(int));

        std::vector<unsigned char> buf(len);
        in.read((char *)buf.data(), len);

        element_init_G1(arr[i], pairing);
        element_from_bytes_compressed(arr[i], buf.data());
    }
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
    if (!infile)
    {
        std::cerr << "Cannot open file: " << filename << std::endl;
        return;
    }

    infile.seekg(0, infile.end);
    size_t key_size = infile.tellg();
    infile.seekg(0, infile.beg);

    cout << "1" << endl;

    int expected = element_length_in_bytes(key);

    cout << "2" << endl;

    if (key_size != (size_t)expected)
    {
        std::cerr << "Error: byte length mismatch. Expected " << expected
                  << ", got " << key_size << std::endl;
        return;
    }

    cout << "3" << endl;

    std::vector<unsigned char> key_bytes(expected);
    infile.read((char *)key_bytes.data(), expected);

    element_from_bytes(key, key_bytes.data());
}
