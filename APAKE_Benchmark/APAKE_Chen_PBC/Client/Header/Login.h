#pragma once

#include <iostream>                          
#include <cstdio>                                    
#include <vector>                   
#include <string>                   
#include <fstream>                    
#include <filesystem>                           
#include <cstring>                 
#include <sstream>
#include <iomanip>

#include <openssl/evp.h>                                     
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <pbc/pbc.h>           

#include "PublicParam.h"                                                                        
namespace fs = std::filesystem;

                           
const char *PRIV_KEY_FILE = "../Key/server_private_key.pem";
const char *PUB_KEY_FILE = "../Key/server_public_key.pem";
const char *SERVER_KEY_FILE = "../Key/server_secret_key.pem";

                                                                               
static void write_u32_le(std::vector<unsigned char> &buf, uint32_t v)
{
    buf.push_back((v >> 0) & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >> 24) & 0xFF);
}

struct ShowProof
{
                           
                                   
    element_t T;       
    element_t c;       
    element_t sm;      
    element_t sa;      
    bool initialized = false;
};

void init_ShowProof(ShowProof &p, pairing_t pairing)
{
    if (p.initialized)
        return;
    element_init_G1(p.T, pairing);
    element_init_Zr(p.c, pairing);
    element_init_Zr(p.sm, pairing);
    element_init_Zr(p.sa, pairing);
    p.initialized = true;
}

void clear_ShowProof(ShowProof &p)
{
    if (!p.initialized)
        return;
    element_clear(p.T);
    element_clear(p.c);
    element_clear(p.sm);
    element_clear(p.sa);
    p.initialized = false;
}

                                            
void HASH4(element_t out_c         , pairing_t pairing,
           element_t g         , element_t T         , element_t R         ,
           const std::vector<unsigned char> &label)
{
                                                            
    int len_g = element_length_in_bytes(g);
    int len_T = element_length_in_bytes(T);
    int len_R = element_length_in_bytes(R);
    std::vector<unsigned char> buf;
    buf.resize(len_g + len_T + len_R + label.size());
    size_t pos = 0;
    element_to_bytes(buf.data() + pos, g);
    pos += len_g;
    element_to_bytes(buf.data() + pos, T);
    pos += len_T;
    element_to_bytes(buf.data() + pos, R);
    pos += len_R;
    if (!label.empty())
    {
        memcpy(buf.data() + pos, label.data(), label.size());
        pos += label.size();
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf.data(), pos, hash);
                     
    element_from_hash(out_c, hash, SHA256_DIGEST_LENGTH);
}

                                                                                                                
bool serialize_show_proof(ShowProof &proof, pairing_t pairing, std::vector<unsigned char> &out)
{
    if (!proof.initialized)
        return false;
    out.clear();

        
    int tlen = element_length_in_bytes(proof.T);
    std::vector<unsigned char> tbuf(tlen);
    element_to_bytes(tbuf.data(), proof.T);
    write_u32_le(out, (uint32_t)tlen);
    out.insert(out.end(), tbuf.begin(), tbuf.end());

        
    int clen = element_length_in_bytes(proof.c);
    std::vector<unsigned char> cbuf(clen);
    element_to_bytes(cbuf.data(), proof.c);
    write_u32_le(out, (uint32_t)clen);
    out.insert(out.end(), cbuf.begin(), cbuf.end());

         
    int smlen = element_length_in_bytes(proof.sm);
    std::vector<unsigned char> smbuf(smlen);
    element_to_bytes(smbuf.data(), proof.sm);
    write_u32_le(out, (uint32_t)smlen);
    out.insert(out.end(), smbuf.begin(), smbuf.end());

         
    int salen = element_length_in_bytes(proof.sa);
    std::vector<unsigned char> sabuf(salen);
    element_to_bytes(sabuf.data(), proof.sa);
    write_u32_le(out, (uint32_t)salen);
    out.insert(out.end(), sabuf.begin(), sabuf.end());

    return true;
}

bool Show(ShowProof &proof_out,
          pairing_t pairing,
          element_t A         ,
          element_t m         ,
          const std::vector<unsigned char> &label,
          element_t g         )
{
                            
    init_ShowProof(proof_out, pairing);

                   
    element_t a, rm, ra, T, R, tmp, c;
    element_init_Zr(a, pairing);
    element_init_Zr(rm, pairing);
    element_init_Zr(ra, pairing);
    element_init_G1(T, pairing);
    element_init_G1(R, pairing);
    element_init_G1(tmp, pairing);          
    element_init_Zr(c, pairing);

                                    
    do
    {
        element_random(a);
    } while (element_is0(a));

    element_printf("A = %B\n", A);
    element_printf("a = %B\n", a);

                 
    element_pow_zn(T, A, a);           

                       
    do
    {
        element_random(rm);
    } while (element_is0(rm));

    do
    {
        element_random(ra);
    } while (element_is0(ra));

                                                          
    element_t neg_rm;
    element_init_Zr(neg_rm, pairing);
    element_neg(neg_rm, rm);              
    element_pow_zn(tmp, T, neg_rm);                 

                    
    element_t tmp2;
    element_init_G1(tmp2, pairing);
    element_pow_zn(tmp2, g, ra);

                     
    element_mul(R, tmp, tmp2);          

    printf("===== Show(): H4 INPUT =====\n");
    element_printf("g = %B\n", g);
    element_printf("T = %B\n", T);
    element_printf("R = %B\n", R);

    printf("label = ");
    for (unsigned char b : label)
        printf("%02X", b);
    printf("\n");
    printf("================================\n");

                             
    HASH4(c, pairing, g, T, R, label);

                                      
    element_t cm;
    element_init_Zr(cm, pairing);
    element_mul(cm, c, m);                          
    element_add(proof_out.sm, rm, cm);                

                         
    element_t ca;
    element_init_Zr(ca, pairing);
    element_mul(ca, c, a);              
    element_add(proof_out.sa, ra, ca);

                  
    element_set(proof_out.T, T);
    element_set(proof_out.c, c);

                   
    element_clear(a);
    element_clear(rm);
    element_clear(ra);
    element_clear(T);
    element_clear(R);
    element_clear(tmp);
    element_clear(c);
    element_clear(neg_rm);
    element_clear(tmp2);
    element_clear(cm);
    element_clear(ca);

    return true;
}

bool ShowVerify(ShowProof &proof,
                pairing_t pairing,
                const element_t W         ,
                element_t gamma         ,
                const std::vector<unsigned char> &label,
                element_t g         )
{
    if (!proof.initialized)
        return false;

    element_t V, tmp1, tmp2, R0, tmp3, neg_sm, neg_c;
    element_init_G1(V, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(R0, pairing);
    element_init_G1(tmp3, pairing);
    element_init_Zr(neg_sm, pairing);
    element_init_Zr(neg_c, pairing);

                  
    element_pow_zn(V, proof.T, gamma);

                     
    element_neg(neg_sm, proof.sm);       
    element_pow_zn(tmp1, proof.T, neg_sm);

                    
    element_pow_zn(tmp2, g, proof.sa);

                       
    element_mul(R0, tmp1, tmp2);

                    
    element_neg(neg_c, proof.c);
    element_pow_zn(tmp3, V, neg_c);

                     
    element_mul(R0, R0, tmp3);

                      
        
                                                  
                                                
                                          
                                                        
                                                
                                                
                                                    
                                                  
                                            
                                                                                     
            
                                      
                                        
                                                                                  
                                
             
                                                                              
                                                           
                                                           
                                                             
                                   
                                 
                                                 
                                                                            
        

    printf("===== ShowVerify(): H4 INPUT =====\n");
    element_printf("g  = %B\n", g);
    element_printf("T  = %B\n", proof.T);
    element_printf("R' = %B\n", R0);

    printf("label = ");
    for (unsigned char b : label)
        printf("%02X", b);
    printf("\n");
    printf("====================================\n");

                            
    element_t c2;
    element_init_Zr(c2, pairing);
    HASH4(c2, pairing, g, proof.T, R0, label);

    bool ok = (element_cmp(c2, proof.c) == 0);

             
    element_clear(V);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(R0);
    element_clear(tmp3);
    element_clear(neg_sm);
    element_clear(neg_c);
    element_clear(c2);

    return ok;
}

EVP_PKEY *load_or_generate_ecdsa_key()
{
    EVP_PKEY *pkey = nullptr;

                         
    std::filesystem::path keydir = std::filesystem::path(PRIV_KEY_FILE).parent_path();
    if (!std::filesystem::exists(keydir))
        std::filesystem::create_directories(keydir);

                               
    FILE *f = fopen(PRIV_KEY_FILE, "rb");
    if (f)
    {
        pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
        fclose(f);
        if (pkey)
        {
            std::cout << "[Info] Loaded existing EC private key\n";
            return pkey;
        }
        std::cerr << "[Warning] Failed to read private key, will generate a new one\n";
    }

                                                                       
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx)
        return nullptr;

    if (1 != EVP_PKEY_keygen_init(ctx))
    {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

                                                                
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1))
    {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (1 != EVP_PKEY_keygen(ctx, &pkey))
    {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);

                                                             
    f = fopen(PRIV_KEY_FILE, "wb");
    if (!f)
    {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

                                                             
    f = fopen(PUB_KEY_FILE, "wb");
    if (!f)
    {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    PEM_write_PUBKEY(f, pkey);
    fclose(f);

    std::cout << "[Info] Generated new EC key pair\n";
    return pkey;
}

bool sign_message(EVP_PKEY *pkey, const std::vector<unsigned char> &msg, std::vector<unsigned char> &signature)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    if (1 != EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey))
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DigestSignUpdate(ctx, msg.data(), msg.size()))
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    size_t siglen = 0;
    if (1 != EVP_DigestSignFinal(ctx, nullptr, &siglen))
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    signature.resize(siglen);

    if (1 != EVP_DigestSignFinal(ctx, signature.data(), &siglen))
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    signature.resize(siglen);
    EVP_MD_CTX_free(ctx);
    return true;
}

bool verify_signature(EVP_PKEY *pubkey, const std::vector<unsigned char> &msg, const std::vector<unsigned char> &signature)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return false;

    if (1 != EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey))
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size()))
    {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int rc = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);

    return rc == 1;
}

                                                                 
bool decrypt_mac_with_pw(const std::string &password,
                         const std::vector<unsigned char> &iv,
                         const std::vector<unsigned char> &ciphertext,                     
                         const std::vector<unsigned char> &tag,
                         std::vector<unsigned char> &plaintext)
{
    auto print_hex = [](const char *title, const std::vector<unsigned char> &v, size_t len = SIZE_MAX)
    {
        std::cout << title;
        if (len == SIZE_MAX) len = v.size();
        for (size_t i = 0; i < len && i < v.size(); ++i) printf("%02X", v[i]);
        std::cout << "\n";
    };

    if (iv.size() != 12) return false;
    if (ciphertext.size() < (size_t)SALT_LEN) return false;             

                                          
    std::vector<unsigned char> salt(SALT_LEN);
    memcpy(salt.data(), ciphertext.data(), SALT_LEN);

                                       
    std::vector<unsigned char> real_ct;
    if (ciphertext.size() > (size_t)SALT_LEN)
    {
        real_ct.assign(ciphertext.begin() + SALT_LEN, ciphertext.end());
    }
    else
    {
        real_ct.clear();
    }

                                          
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                          salt.data(), (int)salt.size(),
                          PBKDF2_ITERS, EVP_sha256(), sizeof(key), key) != 1)
    {
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

                                                           
    std::cout << "----- AES-GCM DEBUG (decrypt - slow) -----\n";
    std::cout << "Password = " << password << "\n";

    std::cout << "Key  = ";
    for (int i = 0; i < 32; i++) printf("%02X", key[i]);
    std::cout << "\n";

    print_hex("Salt = ", salt);
    print_hex("IV   = ", iv);
    print_hex("CT   = ", real_ct);
    print_hex("TAG  = ", tag);
    std::cout << "----------------------------------\n";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { OPENSSL_cleanse(key, sizeof(key)); return false; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

                                                            
    plaintext.resize(real_ct.size());

    int update_len = 0;
    if (!real_ct.empty())
    {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &update_len, real_ct.data(), (int)real_ct.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(key, sizeof(key));
            return false;
        }
    }

                       
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void *)tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + update_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1)
    {
        std::cout << "[ERROR] GCM tag verification FAILED\n";
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

    size_t total_len = (size_t)update_len + (size_t)final_len;
    plaintext.resize(total_len);

                                                              
    std::cout << "Plaintext = ";
    for (size_t i = 0; i < total_len; ++i) printf("%02X", plaintext[i]);
    std::cout << "\n";

    std::cout << "----- AES-GCM decrypt OK -----\n";

    OPENSSL_cleanse(key, sizeof(key));
    return true;
}

int Login(const std::string &password, const std::string &identity)
{
    cout << "************************************Login phase************************************" << endl;
    element_t g, W, gamma;
    element_init_G1(g, pairing);
    element_init_Zr(gamma, pairing);

    cout << "hello" << endl;

    load_from_file(g, GEN_DIR);
    load_from_file(gamma, KEY_DIR);

    cout << "hello2" << endl;

                                               
    element_t y, Y;
    element_init_Zr(y, pairing);
    element_init_G1(Y, pairing);
    do
    {
        element_random(y);
    } while (element_is0(y));
    element_pow_zn(Y, g, y);           

                                  
    int Y_len = element_length_in_bytes(Y);
    std::vector<unsigned char> Y_bytes(Y_len);
    element_to_bytes(Y_bytes.data(), Y);

                                                 
    EVP_PKEY *sk = load_or_generate_ecdsa_key();
    if (!sk)
    {
        element_clear(y);
        element_clear(Y);
        element_clear(g);
        element_clear(W);
        element_clear(gamma);
        pairing_clear(pairing);
        return -2;
    }
    std::vector<unsigned char> sigmaS;
    if (!sign_message(sk, Y_bytes, sigmaS))
    {
        std::cerr << "[Login_PBC] sign_message failed\n";
                     
    }

    EVP_PKEY *pk = load_or_generate_ecdsa_key();
    if (verify_signature(pk, Y_bytes, sigmaS))
    {
        cout << "The signature verification succeeds!" << endl;
    }

    cout << "hello" << endl;

                                             
    unsigned char id_hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(identity.data()), identity.size(), id_hash);
    element_t m;
    element_init_Zr(m, pairing);
    element_from_hash(m, id_hash, SHA256_DIGEST_LENGTH);
    element_printf("m = %B\n", m);

                                                                                           
                                                                  
    std::string cred_file = "../Key/" + identity + "_cred.bin";
    std::ifstream ifs(cred_file, std::ios::binary | std::ios::ate);
    if (!ifs)
    {
        std::cerr << "[Login_PBC] cannot open credential file\n";
                     
        return -1;
    }
    std::streamsize fsize = ifs.tellg();
    ifs.seekg(0, ios::beg);
    std::vector<unsigned char> iv(12);
    ifs.read(reinterpret_cast<char *>(iv.data()), 12);
    std::streamsize cipher_len = fsize - 12 - 16;
    std::vector<unsigned char> ciphertext((size_t)cipher_len);
    ifs.read(reinterpret_cast<char *>(ciphertext.data()), cipher_len);
    std::vector<unsigned char> tag(16);
    ifs.read(reinterpret_cast<char *>(tag.data()), 16);
    ifs.close();

    std::vector<unsigned char> plaintext;
    if (!decrypt_mac_with_pw(password, iv, ciphertext, tag, plaintext))
    {
        std::cerr << "[Login_PBC] decrypt failed\n";
                     
        return -1;
    }

                                               
    element_t A;
    element_init_G1(A, pairing);
    element_from_bytes_vec(A, plaintext);
    element_printf("A after decryption = %B\n", A);
                                     

                       
        
                                                 
                                                 
                                            
                                  
                                       
                                                                              
                                                               
        

                               
    element_t x, X;
    element_init_Zr(x, pairing);
    element_init_G1(X, pairing);
    do
    {
        element_random(x);
    } while (element_is0(x));
    element_pow_zn(X, g, x);

                                          
    std::vector<unsigned char> L;
                     
    int Xlen = element_length_in_bytes(X);
    std::vector<unsigned char> X_bytes(Xlen);
    element_to_bytes(X_bytes.data(), X);
    L.insert(L.end(), X_bytes.begin(), X_bytes.end());
    L.insert(L.end(), Y_bytes.begin(), Y_bytes.end());
    L.insert(L.end(), sigmaS.begin(), sigmaS.end());

    cout << "hello" << endl;

                           
    ShowProof proof;
    init_ShowProof(proof, pairing);
    element_t g_copy;
    element_init_G1(g_copy, pairing);
    element_set(g_copy, g);
    Show(proof, pairing, A, m, L, g_copy);
    bool ok = ShowVerify(proof, pairing, W, gamma, L, g_copy);
    std::cout << "ShowVerify => " << (ok ? "OK" : "FAIL") << std::endl;
    if (!ok)
    {
                     
        clear_ShowProof(proof);
              
        return -1;
    }

                                
    std::vector<unsigned char> out;
    if (!serialize_show_proof(proof, pairing, out))
    {
        std::cerr << "[Login_PBC] serialize_show_proof failed\n";
                     
    }

                                                                                  
    element_t shared_server, shared_client;
    element_init_G1(shared_server, pairing);
    element_init_G1(shared_client, pairing);
    element_pow_zn(shared_server, X, y);       
    element_pow_zn(shared_client, Y, x);       

                                                                                                     
                                                                                              
    std::vector<unsigned char> K_server = derive_session_key_H2(Y_bytes, sigmaS, X_bytes, out, shared_server);
    std::vector<unsigned char> K_client = derive_session_key_H2(Y_bytes, sigmaS, X_bytes, out, shared_client);

                         
    {
        std::ostringstream oss;
        for (unsigned char b : K_server)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << "[Login_PBC] Server-side Session key K_server (hex): " << oss.str() << std::endl;
    }
    {
        std::ostringstream oss;
        for (unsigned char b : K_client)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        std::cout << "[Login_PBC] Client-side Session key K_client (hex): " << oss.str() << std::endl;
    }

                                                
    clear_ShowProof(proof);
    element_clear(y);
    element_clear(Y);
    element_clear(m);
    element_clear(A);
    element_clear(x);
    element_clear(X);
    element_clear(shared_server);
    element_clear(shared_client);
    element_clear(g_copy);
    element_clear(g);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(pk);

    return 0;
}