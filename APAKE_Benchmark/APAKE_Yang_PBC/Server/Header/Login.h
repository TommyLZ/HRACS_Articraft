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
        if (len == SIZE_MAX)
            len = v.size();
        for (size_t i = 0; i < len && i < v.size(); ++i)
            printf("%02X", v[i]);
        std::cout << "\n";
    };

    if (iv.size() != 12)
        return false;
    if (ciphertext.size() < (size_t)SALT_LEN)
        return false;             

                                          
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
    for (int i = 0; i < 32; i++)
        printf("%02X", key[i]);
    std::cout << "\n";

    print_hex("Salt = ", salt);
    print_hex("IV   = ", iv);
    print_hex("CT   = ", real_ct);
    print_hex("TAG  = ", tag);
    std::cout << "----------------------------------\n";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        OPENSSL_cleanse(key, sizeof(key));
        return false;
    }

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
    for (size_t i = 0; i < total_len; ++i)
        printf("%02X", plaintext[i]);
    std::cout << "\n";

    std::cout << "----- AES-GCM decrypt OK -----\n";

    OPENSSL_cleanse(key, sizeof(key));
    return true;
}

int Login(const std::string &password, const std::string &identity)
{
    cout << "************************************Login phase************************************" << endl;
    element_t M, k;
    element_init_G1(M, pairing);
    element_init_Zr(k, pairing);

    std::string M_file = "../Key/M.bin";
    std::ifstream ifs(M_file, std::ios::binary | std::ios::ate);
    if (!ifs)
    {
        std::cerr << "[Login_PBC] cannot open credential file\n";
                     
        return -1;
    }
    std::streamsize fsize = ifs.tellg();
    ifs.seekg(0, ios::beg);
    std::vector<unsigned char> M_iv(12);
    ifs.read(reinterpret_cast<char *>(M_iv.data()), 12);
    std::streamsize cipher_len = fsize - 12 - 16;
    std::vector<unsigned char> M_ciphertext((size_t)cipher_len);
    ifs.read(reinterpret_cast<char *>(M_ciphertext.data()), cipher_len);
    std::vector<unsigned char> M_tag(16);
    ifs.read(reinterpret_cast<char *>(M_tag.data()), 16);
    ifs.close();

    std::vector<unsigned char> M_plain;
    if (!decrypt_mac_with_pw(password, M_iv, M_ciphertext, M_tag, M_plain))
    {
        std::cerr << "[Login_PBC] decrypt failed\n";
                     
        return -1;
    }

    element_from_bytes_vec(M, M_plain);
    element_printf("M after decryption = %B\n", M);

                                                                                                                                              
                                                              
    std::string k_file = "../Key/k.bin";
    std::ifstream iifs(k_file, std::ios::binary | std::ios::ate);
    if (!iifs)
    {
        std::cerr << "[Login_PBC] cannot open credential file: " << k_file << "\n";
        return -1;
    }
    std::streamsize ffsize = iifs.tellg();
    iifs.seekg(0, std::ios::beg);

                                                                               
    if (ffsize < 12 + 16 + SALT_LEN)
    {
        std::cerr << "[Login_PBC] credential file too small or corrupted (size=" << ffsize << ")\n";
        return -1;
    }

                   
    std::vector<unsigned char> k_iv(12);
    iifs.read(reinterpret_cast<char *>(k_iv.data()), (std::streamsize)k_iv.size());
    if (!iifs)
    {
        std::cerr << "[Login_PBC] failed to read IV\n";
        return -1;
    }

                                              
    std::streamsize rem = ffsize - (std::streamsize)k_iv.size();
    if (rem < 16)
    {
        std::cerr << "[Login_PBC] remaining data too small for tag\n";
        return -1;
    }

                                                 
    std::streamsize cipher_len1 = rem - 16;                                
    std::vector<unsigned char> k_ciphertext((size_t)cipher_len1);
    if (cipher_len1 > 0)
    {
        iifs.read(reinterpret_cast<char *>(k_ciphertext.data()), cipher_len1);
        if (!iifs)
        {
            std::cerr << "[Login_PBC] failed to read ciphertext\n";
            return -1;
        }
    }
    else
    {
        k_ciphertext.clear();
    }

          
    std::vector<unsigned char> k_tag(16);
    iifs.read(reinterpret_cast<char *>(k_tag.data()), 16);
    if (!iifs)
    {
        std::cerr << "[Login_PBC] failed to read tag\n";
        return -1;
    }

    iifs.close();

                                                                                                          
    std::vector<unsigned char> k_plain;
    if (!decrypt_mac_with_pw(password, k_iv, k_ciphertext, k_tag, k_plain))
    {
        std::cerr << "[Login_PBC] decrypt failed\n";
        return -1;
    }

                                                                     
    std::cout << "k decrypted, length = " << k_plain.size() << "\n";
    zr_from_bytes(k, k_plain);
    element_printf("k after decryption = %B\n", k);

    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);

    ElGamalCipher ct_s, ct_r, ct_s_star;
    elgamal_cipher_init(ct_s, pairing);
    elgamal_cipher_init(ct_r, pairing);
    elgamal_cipher_init(ct_s_star, pairing);
    ElGamalKeypair kp;
    cout << "int****************************************" << endl;
    load_elgamal_keypair("../Key/elgamal_key", kp);
    cout << "int****************************************" << endl;
    elgamal_encrypt(pairing, kp, r, ct_r);
    load_elgamal_cipher("../Key/s.bin", pairing, ct_s);
    cout << "int2****************************************" << endl;
    elgamal_homomorphic_mul(pairing, ct_r, ct_s, ct_s_star);
    cout << "int3****************************************" << endl;

    element_t x, X, NA;
    element_init_Zr(x, pairing);
    element_init_G1(X, pairing);

    element_random(x);
    element_pow_zn(X, g, x);

    element_init_Zr(NA, pairing);
    element_random(NA);

    cout << "int****************************************" << endl;

    ElGamalCipher NA_ct;

    cout << "hello" << endl;
    elgamal_encrypt(pairing, kp, NA, NA_ct);

    cout << "helloee" << endl;
    PublicParams pp;
    setup_params(pp);

    cout << "helloee" << endl;
    ProverSecrets sec;
    prover_init(sec, pp, M, k, r, identity);

    cout << "hellocc" << endl;
                                                       
    element_t r_u, r_k, r_gamma, r_alpha, r_talpha;
    element_init_Zr(r_u, pairing);
    element_init_Zr(r_k, pairing);
    element_init_Zr(r_gamma, pairing);
    element_init_Zr(r_alpha, pairing);
    element_init_Zr(r_talpha, pairing);

    element_random(r_u);
    element_random(r_k);
    element_random(r_gamma);
    element_random(r_alpha);
    element_random(r_talpha);

    cout << "helloff" << endl;
                    
    Commitment cmt;
    cout << "hellooof" << endl;
    prover_commit(cmt, sec, pp, r_u, r_k, r_gamma, r_alpha, r_talpha);

    cout << "hellokk" << endl;

                                                                                                                        
    element_t sp;
    element_init_Zr(sp, pairing);
    elgamal_decrypt(pairing, kp, ct_s_star, sp);

    element_t y, Y;
    element_init_Zr(y, pairing);
    element_init_G1(Y, pairing);

    element_random(y);
    element_pow_zn(Y, g, y);

    element_t NAp;
    element_init_Zr(NAp, pairing);
    elgamal_decrypt(pairing, kp, NA_ct, NAp);

    vector<unsigned char> key = generate_hmac_key();
    cout << "[KEY] " << bytes_to_hex(key) << endl;
                  
    vector<unsigned char> mac = compute_mac_hmac_sha256(key, NAp, Y, X);
    cout << "[PROVER] MAC hex: " << bytes_to_hex(mac) << endl;

    element_t NB;
    element_init_Zr(NB, pairing);
    element_random(NB);

    bool ok = verify_mac_hmac_sha256(key, NAp, Y, X, mac);

    cout << "[VERIFIER] MAC verify result = "
         << (ok ? "VALID" : "INVALID") << endl;

                                        
    element_t c;
    element_init_Zr(c, pairing);
    element_random(c);

                     
    Response res;
    prover_respond(res, sec, c, r_u, r_k, r_gamma, r_alpha, r_talpha, pp);

                      
    ok = verifier_check(cmt, res, c, pp);
    cout << (ok ? "[RESULT] Verification succeeded." : "[RESULT] Verification FAILED.") << endl;

                                                                                  
    element_t shared_server, shared_client;
    element_init_G1(shared_server, pairing);
    element_init_G1(shared_client, pairing);
    element_pow_zn(shared_server, X, y);       
    element_pow_zn(shared_client, Y, x);       

    int NA_len = element_length_in_bytes(NA);
    std::vector<unsigned char> NA_bytes(NA_len);
    element_to_bytes(NA_bytes.data(), NA);

    int NB_len = element_length_in_bytes(NB);
    std::vector<unsigned char> NB_bytes(NB_len);
    element_to_bytes(NB_bytes.data(), NB);

    std::vector<unsigned char> K_server = derive_session_key_H2(NA_bytes, NB_bytes, shared_server);
    std::vector<unsigned char> K_client = derive_session_key_H2(NA_bytes, NB_bytes, shared_client);

                         
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

                                                               
    element_clear(c);
    element_clear(r_u);
    element_clear(r_k);
    element_clear(r_gamma);
    element_clear(r_alpha);
    element_clear(r_talpha);
    element_clear(sec.M);
    element_clear(sec.alpha);
    element_clear(sec.k);
    element_clear(sec.gamma);
    element_clear(sec.u);

    element_clear(cmt.T1);
    element_clear(cmt.T2);
    element_clear(cmt.R1);
    element_clear(cmt.R2);
    element_clear(cmt.R3);
    element_clear(res.su);
    element_clear(res.s_gamma);
    element_clear(res.sk);
    element_clear(res.s_alpha);
    element_clear(res.s_talpha);

    element_clear(pp.g0);
    element_clear(pp.g1);
    element_clear(pp.W);
    element_clear(pp.h);
    element_clear(pp.a);
    element_clear(pp.B);
    element_clear(pp.d);

    return 0;
}