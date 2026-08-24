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

struct BBS_Sign
{
    element_t M;
    element_t k;
    element_t s;
    bool initialized = false;
    void init(pairing_t pairing)
    {
        if (initialized)
            return;
        element_init_G1(M, pairing);
        element_init_Zr(k, pairing);
        element_init_Zr(s, pairing);
        initialized = true;
    }
    void clear()
    {
        if (!initialized)
            return;
        element_clear(M);
        element_clear(k);
        element_clear(s);
        initialized = false;
    }
};

bool bbs_sign(pairing_t pairing,
              const string &priv_path,
              const string &a_path,
              const string &b_path,
              const string &d_path,
              const string &h_path,
              const string &W_path,
              const string &message,
              BBS_Sign &sig_out)
{

    element_t chi;
    element_init_Zr(chi, pairing);
    if (!load_element_from_file(chi, pairing, priv_path, 3))
    {
        cerr << "[bbs_sign] cannot load private key chi\n";
        element_clear(chi);
        return false;
    }

    element_t a, b, d, h, W;
    element_init_G1(a, pairing);
    element_init_G1(b, pairing);
    element_init_G1(d, pairing);
    element_init_G2(h, pairing);
    element_init_G2(W, pairing);

    if (!load_into_inited_element_from_file(a, a_path) ||
        !load_into_inited_element_from_file(b, b_path) ||
        !load_into_inited_element_from_file(d, d_path) ||
        !load_into_inited_element_from_file(h, h_path) ||
        !load_into_inited_element_from_file(W, W_path))
    {
        cerr << "[bbs_sign] cannot load public parameters\n";
        element_clear(chi);
        element_clear(a);
        element_clear(b);
        element_clear(d);
        element_clear(h);
        element_clear(W);
        return false;
    }

    element_t m;
    element_init_Zr(m, pairing);
    element_from_hash(m, (void *)message.data(), message.size());

    element_t k, s, denom, denom_inv;
    element_init_Zr(k, pairing);
    element_init_Zr(s, pairing);
    element_init_Zr(denom, pairing);
    element_init_Zr(denom_inv, pairing);

    do
    {
        element_random(k);

        element_add(denom, k, chi);
    } while (element_is0(denom));

    element_random(s);

    element_t a_pow_m, b_pow_s, base;
    element_init_G1(a_pow_m, pairing);
    element_init_G1(b_pow_s, pairing);
    element_init_G1(base, pairing);

    element_pow_zn(a_pow_m, a, m);
    element_pow_zn(b_pow_s, b, s);
    element_mul(base, a_pow_m, b_pow_s);
    element_mul(base, base, d);

    element_invert(denom_inv, denom);

    element_init_G1(sig_out.M, pairing);
    element_pow_zn(sig_out.M, base, denom_inv);

    element_set(sig_out.k, k);
    element_set(sig_out.s, s);

    element_clear(chi);
    element_clear(a);
    element_clear(b);
    element_clear(d);
    element_clear(h);
    element_clear(W);
    element_clear(m);
    element_clear(k);
    element_clear(s);
    element_clear(denom);
    element_clear(denom_inv);
    element_clear(a_pow_m);
    element_clear(b_pow_s);
    element_clear(base);
    return true;
}

bool bbs_verify(pairing_t pairing,
                string &a_path,
                string &b_path,
                string &d_path,
                string &h_path,
                string &W_path,
                string &message,
                BBS_Sign &sig)
{

    element_t a, b, d, h, W;
    element_init_G1(a, pairing);
    element_init_G1(b, pairing);
    element_init_G1(d, pairing);
    element_init_G2(h, pairing);
    element_init_G2(W, pairing);

    if (!load_into_inited_element_from_file(a, a_path) ||
        !load_into_inited_element_from_file(b, b_path) ||
        !load_into_inited_element_from_file(d, d_path) ||
        !load_into_inited_element_from_file(h, h_path) ||
        !load_into_inited_element_from_file(W, W_path))
    {
        cerr << "[bbs_verify] cannot load public parameters\n";
        element_clear(a);
        element_clear(b);
        element_clear(d);
        element_clear(h);
        element_clear(W);
        return false;
    }

    element_t m;
    element_init_Zr(m, pairing);
    element_from_hash(m, (void *)message.data(), message.size());

    element_t h_pow_k;
    element_init_G2(h_pow_k, pairing);
    element_pow_zn(h_pow_k, h, sig.k);

    element_t W_hk;
    element_init_G2(W_hk, pairing);
    element_mul(W_hk, W, h_pow_k);

    element_t left, t1, t2, t3, right;
    element_init_GT(left, pairing);
    element_init_GT(t1, pairing);
    element_init_GT(t2, pairing);
    element_init_GT(t3, pairing);
    element_init_GT(right, pairing);

    pairing_apply(left, sig.M, W_hk, pairing);

    pairing_apply(t1, a, h, pairing);
    pairing_apply(t2, b, h, pairing);
    pairing_apply(t3, d, h, pairing);

    element_pow_zn(t1, t1, m);
    element_pow_zn(t2, t2, sig.s);

    element_mul(right, t1, t2);
    element_mul(right, right, t3);

    bool ok = (element_cmp(left, right) == 0);

    element_clear(a);
    element_clear(b);
    element_clear(d);
    element_clear(h);
    element_clear(W);
    element_clear(m);
    element_clear(h_pow_k);
    element_clear(W_hk);
    element_clear(left);
    element_clear(t1);
    element_clear(t2);
    element_clear(t3);
    element_clear(right);

    return ok;
}

bool bbs_keygen(pairing_t pairing,
                const string &priv_path,
                const string &h_path,
                const string &W_path,
                const string &a_path,
                const string &b_path,
                const string &d_path)
{

    filesystem::path dir = filesystem::path(priv_path).parent_path();
    if (!filesystem::exists(dir))
        filesystem::create_directories(dir);

    if (filesystem::exists(priv_path) && filesystem::exists(h_path) &&
        filesystem::exists(W_path) && filesystem::exists(a_path) &&
        filesystem::exists(b_path) && filesystem::exists(d_path))
    {
        cout << "[bbs_keygen] key files exist, skipping generation.\n";
        return true;
    }

    element_t chi, h, W, a, b, d;
    element_init_Zr(chi, pairing);
    element_init_G2(h, pairing);
    element_init_G2(W, pairing);
    element_init_G1(a, pairing);
    element_init_G1(b, pairing);
    element_init_G1(d, pairing);

    element_random(chi);

    element_random(a);
    element_random(b);
    element_random(d);
    element_random(h);

    element_pow_zn(W, h, chi);

    bool ok = true;
    if (!save_element_to_file(priv_path, chi))
        ok = false;
    if (!save_element_to_file(h_path, h))
        ok = false;
    if (!save_element_to_file(W_path, W))
        ok = false;
    if (!save_element_to_file(a_path, a))
        ok = false;
    if (!save_element_to_file(b_path, b))
        ok = false;
    if (!save_element_to_file(d_path, d))
        ok = false;

    element_clear(chi);
    element_clear(h);
    element_clear(W);
    element_clear(a);
    element_clear(b);
    element_clear(d);

    return ok;
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

    string priv_path = "../Key/bbs_chi.bin";
    string h_path = "../Key/bbs_h.bin";
    string W_path = "../Key/bbs_W.bin";
    string a_path = "../Key/bbs_a.bin";
    string b_path = "../Key/bbs_b.bin";
    string d_path = "../Key/bbs_d.bin";

    if (!bbs_keygen(pairing, priv_path, h_path, W_path, a_path, b_path, d_path))
    {
        cerr << "Key generation failed\n";
        return 1;
    }
    cout << "Key ready.\n";

    BBS_Sign sig;
    sig.init(pairing);
    string message = "hello world";
    if (!bbs_sign(pairing, priv_path, a_path, b_path, d_path, h_path, W_path, message, sig))
    {
        cerr << "Sign failed\n";
        sig.clear();
        return 1;
    }
    cout << "Signed. Signature components:\n";
    element_printf("M = %B\n", sig.M);
    element_printf("k = %B\n", sig.k);
    element_printf("s = %B\n", sig.s);

    vector<unsigned char> M_vec = element_to_bytes_vec(sig.M);
    vector<unsigned char> enc_M_mac, M_tag, M_iv;
    if (!encrypt_mac_with_pw(password, M_vec, enc_M_mac, M_tag, M_iv))
    {
        cerr << "[Error] AES-GCM encryption failed" << endl;
        return -1;
    }

    string M_file = "../Key/M.bin";
    ofstream Mofs(M_file, ios::binary);
    Mofs.write((char *)M_iv.data(), M_iv.size());
    Mofs.write((char *)enc_M_mac.data(), enc_M_mac.size());
    Mofs.write((char *)M_tag.data(), M_tag.size());
    Mofs.close();

    cout << "M stored to " << M_file << endl;

    vector<unsigned char> k_vec = zr_to_bytes(sig.k);
    cout << "hello" << endl;
    vector<unsigned char> enc_k_mac, k_tag, k_iv;
    if (!encrypt_mac_with_pw(password, k_vec, enc_k_mac, k_tag, k_iv))
    {
        cerr << "[Error] AES-GCM encryption failed" << endl;
        return -1;
    }

    string k_file = "../Key/k.bin";
    ofstream k_ofs(k_file, ios::binary);
    k_ofs.write((char *)k_iv.data(), k_iv.size());
    k_ofs.write((char *)enc_k_mac.data(), enc_k_mac.size());
    k_ofs.write((char *)k_tag.data(), k_tag.size());
    k_ofs.close();

    cout << "k stored to " << k_file << endl;

    ElGamalKeypair kp;
    elgamal_keypair_init(kp, pairing);
    elgamal_keygen(pairing, kp, "../Key/elgamal_key");

    element_t m;
    element_init_G1(m, pairing);
    element_pow_zn(m, g, sig.s);

    ElGamalCipher s;
    elgamal_encrypt(pairing, kp, m, s);

    string s_file = "../Key/s.bin";
    save_elgamal_cipher(s_file, s);

    sig.clear();
    return 0;
}
