#pragma once

#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>
#include <string>
#include "PublicParam.h"

extern pairing_t pairing;
extern element_t g;

using namespace std;
namespace fs = std::filesystem;

bool compute_pbc_mac_sdh(pairing_t pairing, element_t gamma, element_t m, element_t G, element_t A)
{
    element_t tmp;
    element_init_Zr(tmp, pairing);
    element_add(tmp, gamma, m);
    element_invert(tmp, tmp);
    element_pow_zn(A, G, tmp);
    element_clear(tmp);
    return true;
}

std::vector<unsigned char> elem_to_bytes(element_t e)
{
    int len = element_length_in_bytes(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), e);
    return buf;
}

void append_elem(std::vector<unsigned char> &blob, element_t e)
{
    auto v = elem_to_bytes(e);
    blob.insert(blob.end(), v.begin(), v.end());
}

void hash_elements_to_Zr(element_t out,
                         element_t g,
                         element_t W,
                         element_t m,
                         element_t A,
                         element_t R1,
                         element_t R2)
{
    std::vector<unsigned char> blob;
    blob.reserve(4096);

    append_elem(blob, g);
    append_elem(blob, W);
    append_elem(blob, m);
    append_elem(blob, A);
    append_elem(blob, R1);
    append_elem(blob, R2);

    element_from_hash(out, blob.data(), blob.size());
}

bool nizk_prove(pairing_t pairing,
                element_t W, element_t m, element_t A, element_t gamma,
                element_t &c, element_t &s)
{
    element_t r, R1, R2, tmp;

    element_init_Zr(r, pairing);
    element_init_G1(R1, pairing);
    element_init_G1(R2, pairing);
    element_init_Zr(tmp, pairing);

    element_random(r);

    element_pow_zn(R1, A, r);
    element_pow_zn(R2, g, r);

    element_printf("g = %B\n", g);
    element_printf("W = %B\n", W);
    element_printf("m = %B\n", m);
    element_printf("A = %B\n", A);
    element_printf("R1 = %B\n", R1);
    element_printf("R2 = %B\n", R2);

    element_init_Zr(c, pairing);
    hash_elements_to_Zr(c, g, W, m, A, R1, R2);

    element_init_Zr(s, pairing);
    element_mul(tmp, c, gamma);
    element_add(s, r, tmp);

    element_clear(r);
    element_clear(R1);
    element_clear(R2);
    element_clear(tmp);

    return true;
}

std::vector<unsigned char> zr_to_bytes(element_t z)
{
    int len = element_length_in_bytes(z);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), z);
    return buf;
}

std::vector<unsigned char> g1_to_bytes(element_t P)
{
    int len = element_length_in_bytes(P);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), P);
    return buf;
}

void hash_to_Zr(element_t out, const std::vector<unsigned char> &blob)
{

    element_from_hash(out, (void *)blob.data(), blob.size());
}

bool nizk_verify(pairing_t pairing,
                 element_t W,
                 element_t m,
                 element_t A,
                 element_t c,
                 element_t s)
{

    element_t cm, s_add_cm, c_inv, R1p, tmp1;
    element_init_Zr(cm, pairing);
    element_init_Zr(s_add_cm, pairing);
    element_init_Zr(c_inv, pairing);
    element_init_G1(R1p, pairing);
    element_init_G1(tmp1, pairing);

    element_mul(cm, c, m);

    element_add(s_add_cm, s, cm);

    element_pow_zn(tmp1, A, s_add_cm);

    element_neg(c_inv, c);

    element_pow_zn(R1p, g, c_inv);
    element_mul(R1p, tmp1, R1p);

    element_t R2p, tmp2;
    element_init_G1(R2p, pairing);
    element_init_G1(tmp2, pairing);

    element_pow_zn(tmp1, g, s);

    element_pow_zn(tmp2, W, c_inv);

    element_mul(R2p, tmp1, tmp2);

    element_printf("g = %B\n", g);
    element_printf("W = %B\n", W);
    element_printf("m = %B\n", m);
    element_printf("A = %B\n", A);
    element_printf("R1' = %B\n", R1p);
    element_printf("R2' = %B\n", R2p);

    cout << "nn" << endl;

    element_t c0;
    element_init_Zr(c0, pairing);
    hash_elements_to_Zr(c0, g, W, m, A, R1p, R2p);

    cout << "babe" << endl;

    printf("[c0] = ");
    element_printf("%B\n", c0);

    printf("[c ] = ");
    element_printf("%B\n", c);

    bool eq = element_cmp(c0, c) == 0;

    element_clear(cm);
    element_clear(s_add_cm);
    element_clear(c_inv);
    element_clear(R1p);
    element_clear(tmp1);
    element_clear(R2p);
    element_clear(tmp2);
    element_clear(c0);

    return eq;
}

bool encrypt_mac_with_pw(const std::string &password,
                         const std::vector<unsigned char> &plaintext,
                         std::vector<unsigned char> &ciphertext,
                         std::vector<unsigned char> &tag,
                         std::vector<unsigned char> &iv)
{
    auto print_hex = [](const char *title, const std::vector<unsigned char> &v)
    {
        std::cout << title;
        for (auto b : v)
            printf("%02X", b);
        std::cout << "\n";
    };

    std::vector<unsigned char> salt(SALT_LEN);
    if (RAND_bytes(salt.data(), (int)salt.size()) != 1)
        return false;

    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                          salt.data(), (int)salt.size(),
                          PBKDF2_ITERS, EVP_sha256(), sizeof(key), key) != 1)
    {
        return false;
    }

    iv.resize(12);
    if (RAND_bytes(iv.data(), (int)iv.size()) != 1)
    {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    {
        unsigned char burn_buf[32];
        for (int i = 0; i < BURN_ROUNDS; ++i)
        {

            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(mdctx, key, sizeof(key));
            EVP_DigestUpdate(mdctx, iv.data(), iv.size());
            unsigned int ctr = (unsigned int)i;
            EVP_DigestUpdate(mdctx, &ctr, sizeof(ctr));
            unsigned int outl = 0;
            EVP_DigestFinal_ex(mdctx, burn_buf, &outl);
            EVP_MD_CTX_free(mdctx);
        }
    }

    std::cout << "----- AES-GCM DEBUG (encrypt - slow) -----\n";
    std::cout << "Password = " << password << "\n";

    std::cout << "Key  = ";
    for (int i = 0; i < 32; i++)
        printf("%02X", key[i]);
    std::cout << "\n";

    print_hex("Salt = ", salt);
    print_hex("IV   = ", iv);
    print_hex("PT   = ", plaintext);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    std::vector<unsigned char> real_ct(plaintext.size());
    int outlen = 0;
    if (!plaintext.empty())
    {
        if (EVP_EncryptUpdate(ctx, real_ct.data(), &outlen, plaintext.data(), (int)plaintext.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(key, sizeof(key));
            return false;
        }
    }

    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, real_ct.data() + outlen, &tmplen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }
    outlen += tmplen;
    real_ct.resize(outlen);

    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.clear();
    ciphertext.insert(ciphertext.end(), salt.begin(), salt.end());
    ciphertext.insert(ciphertext.end(), real_ct.begin(), real_ct.end());

    print_hex("CT (salt||ct) = ", ciphertext);
    print_hex("TAG  = ", tag);
    std::cout << "-----------------------------------\n";

    OPENSSL_cleanse(key, sizeof(key));
    return true;
}

int Registration(const string &password, const string &identity)
{
    cout << "************************************Registration phase**************************************************" << endl;

    vector<unsigned char> hash_id(32);
    SHA256((const unsigned char *)identity.data(), identity.size(), hash_id.data());

    cout << "ss" << endl;

    element_t m, gamma, W, A, c, s;
    element_init_Zr(m, pairing);
    element_init_Zr(gamma, pairing);
    element_init_G1(W, pairing);
    element_init_G1(A, pairing);

    cout << "yy" << endl;

    if (!file_exists(GEN_DIR) || !file_exists(KEY_DIR))
    {
        cout << "[Registration] SDH params not found, generating..." << endl;
        element_random(gamma);
        element_pow_zn(W, g, gamma);

        save_to_file(g, GEN_DIR);
        cout << "he" << endl;
        save_to_file(gamma, KEY_DIR);
    }
    else
    {
        load_from_file(g, GEN_DIR);
        load_from_file(gamma, KEY_DIR);
        element_pow_zn(W, g, gamma);
    }

    cout << "yea" << endl;

    element_from_hash(m, hash_id.data(), hash_id.size());

    cout << "hh" << endl;

    compute_pbc_mac_sdh(pairing, gamma, m, g, A);

    cout << "jj" << endl;

    nizk_prove(pairing, W, m, A, gamma, c, s);

    cout << "cc" << endl;

    nizk_verify(pairing, W, m, A, c, s);

    vector<unsigned char> mac_vec = element_to_bytes_vec(A);

    vector<unsigned char> enc_mac, tag, iv;
    if (!encrypt_mac_with_pw(password, mac_vec, enc_mac, tag, iv))
    {
        cerr << "[Error] AES-GCM encryption failed" << endl;
        return -1;
    }

    ensure_key_dir();
    string cred_file = string(SDH_PARAM_FILE) + "/" + identity + "_cred.bin";
    ofstream ofs(cred_file, ios::binary);
    ofs.write((char *)iv.data(), iv.size());
    ofs.write((char *)enc_mac.data(), enc_mac.size());
    ofs.write((char *)tag.data(), tag.size());
    ofs.close();

    cout << "[Registration] Credential stored to " << cred_file << endl;

    element_clear(m);
    element_clear(gamma);
    element_clear(W);
    element_clear(A);
    element_clear(c);
    element_clear(s);

    return 0;
}