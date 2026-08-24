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

#include <openssl/hmac.h>
#include <openssl/rand.h>

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

vector<unsigned char> zr_to_bytes(element_t z)
{
    int len = element_length_in_bytes(z);                     
    vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), z);
    return buf;
}

bool zr_from_bytes(element_t z, vector<unsigned char> &buf)
{
                                                                 
    if (element_from_bytes(z, buf.data()) != 0)
        return false;
    return true;
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
    const vector<unsigned char> &NA_bytes,
    const vector<unsigned char> &NB_bytes,
    element_t shared_point)
{
    vector<unsigned char> data;
    data.insert(data.end(), NA_bytes.begin(), NA_bytes.end());
    data.insert(data.end(), NB_bytes.begin(), NB_bytes.end());

    vector<unsigned char> S_bytes = element_to_bytes_vec(shared_point);
    data.insert(data.end(), S_bytes.begin(), S_bytes.end());

    return sha256_vec(data);            
}

                                                                                       
bool save_element_to_file(const string &path, element_t e)
{
    int len = element_length_in_bytes(e);
    vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), e);
    ofstream ofs(path, ios::binary);
    if (!ofs)
        return false;
    uint32_t L = (uint32_t)len;
    ofs.write(reinterpret_cast<const char *>(&L), sizeof(L));
    ofs.write(reinterpret_cast<const char *>(buf.data()), len);
    ofs.close();
    return true;
}

bool load_element_from_file(element_t e, pairing_t pairing, const string &path, int init_type)
{
                                        
    if (!filesystem::exists(path))
        return false;
    ifstream ifs(path, ios::binary);
    if (!ifs)
        return false;
    uint32_t L = 0;
    ifs.read(reinterpret_cast<char *>(&L), sizeof(L));
    vector<unsigned char> buf(L);
    ifs.read(reinterpret_cast<char *>(buf.data()), L);
    ifs.close();

                         
    if (init_type == 1)
        element_init_G1(e, pairing);
    else if (init_type == 2)
        element_init_G2(e, pairing);
    else
        element_init_Zr(e, pairing);

    element_from_bytes(e, buf.data());
    return true;
}

                                                       
vector<unsigned char> element_to_bytes_vec_compressed(element_t e)
{
    int len = element_length_in_bytes_compressed(e);
    vector<unsigned char> buf(len);
    element_to_bytes_compressed(buf.data(), e);
    return buf;
}
bool element_from_bytes_vec_compressed(element_t e, vector<unsigned char> &buf)
{
                              
    if (buf.empty())
        return false;
    element_from_bytes_compressed(e, buf.data());
    return true;
}

                                                                           
bool load_into_inited_element_from_file(element_t e, const string &path)
{
    if (!filesystem::exists(path))
        return false;
    ifstream ifs(path, ios::binary);
    if (!ifs)
        return false;
    uint32_t L = 0;
    ifs.read(reinterpret_cast<char *>(&L), sizeof(L));
    vector<unsigned char> buf(L);
    ifs.read(reinterpret_cast<char *>(buf.data()), L);
    ifs.close();
    element_from_bytes(e, buf.data());
    return true;
}

                                              
              
                    
struct ElGamalKeypair
{
    element_t g;                             
    element_t pk;                 
    element_t sk;           
    bool initialized = false;
};

void elgamal_keypair_init(ElGamalKeypair &kp, pairing_t pairing)
{
    if (kp.initialized)
        return;
    element_init_G1(kp.g, pairing);
    element_init_G1(kp.pk, pairing);
    element_init_Zr(kp.sk, pairing);
    kp.initialized = true;
}
void elgamal_keypair_clear(ElGamalKeypair &kp)
{
    if (!kp.initialized)
        return;
    element_clear(kp.g);
    element_clear(kp.pk);
    element_clear(kp.sk);
    kp.initialized = false;
}

                                                       
bool save_elgamal_keypair(const string &path_prefix, ElGamalKeypair &kp)
{
    if (!kp.initialized)
        return false;
                                          
    auto g_bytes = element_to_bytes_vec_compressed(kp.g);
    auto pk_bytes = element_to_bytes_vec_compressed(kp.pk);
    auto sk_bytes = zr_to_bytes(kp.sk);

    std::ofstream f(path_prefix + ".g", std::ios::binary);
    if (!f)
        return false;
    uint32_t u;
    u = (uint32_t)g_bytes.size();
    f.write((char *)&u, sizeof(u));
    f.write((char *)g_bytes.data(), g_bytes.size());
    f.close();

    f.open(path_prefix + ".pk", std::ios::binary);
    if (!f)
        return false;
    u = (uint32_t)pk_bytes.size();
    f.write((char *)&u, sizeof(u));
    f.write((char *)pk_bytes.data(), pk_bytes.size());
    f.close();

    f.open(path_prefix + ".sk", std::ios::binary);
    if (!f)
        return false;
    u = (uint32_t)sk_bytes.size();
    f.write((char *)&u, sizeof(u));
    f.write((char *)sk_bytes.data(), sk_bytes.size());
    f.close();

    return true;
}
bool load_elgamal_keypair(const string &path_prefix, ElGamalKeypair &kp)
{
    if (!kp.initialized)
        return false;
             
    std::ifstream f(path_prefix + ".g", std::ios::binary);
    if (!f)
        return false;
    uint32_t u;
    f.read((char *)&u, sizeof(u));
    vector<unsigned char> gbuf(u);
    f.read((char *)gbuf.data(), u);
    f.close();
    element_from_bytes_vec_compressed(kp.g, gbuf);

              
    f.open(path_prefix + ".pk", std::ios::binary);
    if (!f)
        return false;
    f.read((char *)&u, sizeof(u));
    vector<unsigned char> pkbuf(u);
    f.read((char *)pkbuf.data(), u);
    f.close();
    element_from_bytes_vec_compressed(kp.pk, pkbuf);

              
    f.open(path_prefix + ".sk", std::ios::binary);
    if (!f)
        return false;
    f.read((char *)&u, sizeof(u));
    vector<unsigned char> skbuf(u);
    f.read((char *)skbuf.data(), u);
    f.close();
    zr_from_bytes(kp.sk, skbuf);

    return true;
}

                                                                      
bool elgamal_keygen(pairing_t pairing, ElGamalKeypair &kp, const string &path_prefix)
{
    elgamal_keypair_init(kp, pairing);

               
    if (load_elgamal_keypair(path_prefix, kp))
    {
        cout << "[elgamal] loaded keypair from disk\n";
        return true;
    }

                                                                          
    element_random(kp.g);                                          
    element_random(kp.sk);                               
    element_pow_zn(kp.pk, kp.g, kp.sk);            

           
    if (!save_elgamal_keypair(path_prefix, kp))
    {
        cout << "[elgamal] warning: failed to save keypair\n";
    }
    else
    {
        cout << "[elgamal] saved keypair\n";
    }
    return true;
}

                                         
                                    
struct ElGamalCipher
{
    element_t c1;
    element_t c2;
    bool initialized = false;
};
void elgamal_cipher_init(ElGamalCipher &c, pairing_t pairing)
{
    if (c.initialized)
        return;
    element_init_G1(c.c1, pairing);
    element_init_G1(c.c2, pairing);
    c.initialized = true;
}
void elgamal_cipher_clear(ElGamalCipher &c)
{
    if (!c.initialized)
        return;
    element_clear(c.c1);
    element_clear(c.c2);
    c.initialized = false;
}

                                                      
bool elgamal_encrypt(pairing_t pairing, ElGamalKeypair &kp, element_t M, ElGamalCipher &out)
{
    if (!kp.initialized)
        return false;
    elgamal_cipher_init(out, pairing);

    element_t r, tmp;
    element_init_Zr(r, pairing);
    element_init_G1(tmp, pairing);

    element_random(r);
    element_pow_zn(out.c1, kp.g, r);            
    element_pow_zn(tmp, kp.pk, r);                
    element_mul(out.c2, M, tmp);                     

    element_clear(r);
    element_clear(tmp);
    return true;
}

                           
bool elgamal_decrypt(pairing_t pairing, ElGamalKeypair &kp, ElGamalCipher &c, element_t M_out)
{
    if (!kp.initialized)
        return false;
    element_t tmp;
    element_init_G1(tmp, pairing);

    element_pow_zn(tmp, c.c1, kp.sk);              
    element_invert(tmp, tmp);                             
    element_mul(M_out, c.c2, tmp);                   

    element_clear(tmp);
    return true;
}

                                                         
                                         
bool elgamal_homomorphic_mul(pairing_t pairing, ElGamalCipher &a, ElGamalCipher &b, ElGamalCipher &out)
{
    elgamal_cipher_init(out, pairing);
    element_mul(out.c1, a.c1, b.c1);
    element_mul(out.c2, a.c2, b.c2);
    return true;
}

                                                        
bool elgamal_rerandomize(pairing_t pairing, ElGamalKeypair &kp, ElGamalCipher &c)
{
    element_t t, t1, t2;
    element_init_Zr(t, pairing);
    element_init_G1(t1, pairing);
    element_init_G1(t2, pairing);

    element_random(t);
    element_pow_zn(t1, kp.g, t);        
    element_pow_zn(t2, kp.pk, t);        

    element_mul(c.c1, c.c1, t1);
    element_mul(c.c2, c.c2, t2);

    element_clear(t);
    element_clear(t1);
    element_clear(t2);
    return true;
}

                                                               
bool save_elgamal_cipher(const string &path, ElGamalCipher &c)
{
    if (!c.initialized)
        return false;

                                    
    auto c1_bytes = element_to_bytes_vec_compressed(c.c1);
    auto c2_bytes = element_to_bytes_vec_compressed(c.c2);

    ofstream ofs(path, ios::binary);
    if (!ofs)
        return false;

    uint32_t L1 = (uint32_t)c1_bytes.size();
    ofs.write((char *)&L1, sizeof(L1));
    ofs.write((char *)c1_bytes.data(), L1);

    uint32_t L2 = (uint32_t)c2_bytes.size();
    ofs.write((char *)&L2, sizeof(L2));
    ofs.write((char *)c2_bytes.data(), L2);

    ofs.close();
    return true;
}

                                                               
bool load_elgamal_cipher(const string &path, pairing_t pairing, ElGamalCipher &c)
{
    elgamal_cipher_init(c, pairing);

    if (!filesystem::exists(path))
        return false;
    ifstream ifs(path, ios::binary);
    if (!ifs)
        return false;

    uint32_t L1, L2;

              
    ifs.read((char *)&L1, sizeof(L1));
    vector<unsigned char> buf1(L1);
    ifs.read((char *)buf1.data(), L1);
    element_from_bytes_compressed(c.c1, buf1.data());

              
    ifs.read((char *)&L2, sizeof(L2));
    vector<unsigned char> buf2(L2);
    ifs.read((char *)buf2.data(), L2);
    element_from_bytes_compressed(c.c2, buf2.data());

    ifs.close();
    return true;
}

                                    
void print_elem(const char *label, element_t &e)
{
    char *s = NULL;
    int len = element_length_in_bytes_compressed(e);
    s = (char *)malloc(len * 2 + 10);
    element_snprint(s, len * 2 + 10, e);
    cout << label << " : " << s << endl;
    free(s);
}

                                      
struct PublicParams
{
    element_t g0;      
    element_t g1;      
    element_t W;       
    element_t h;       
    element_t a;       
    element_t B;       
    element_t d;       
};

                               
struct ProverSecrets
{
    element_t M;                            
    element_t alpha;      
    element_t k;          
    element_t gamma;      
    element_t u;
                                                   
};

                                         
struct Commitment
{
    element_t T1;      
    element_t T2;      
    element_t R1;      
    element_t R2;      
    element_t R3;      
};

                                                       
struct Response
{
    element_t su;            
    element_t s_gamma;       
    element_t sk;            
    element_t s_alpha;       
    element_t s_talpha;      
};

                                                     
void setup_params(PublicParams &pp)
{
                          
    element_init_G1(pp.g0, pairing);
    element_init_G1(pp.g1, pairing);
    element_init_G2(pp.W, pairing);
    element_init_G2(pp.h, pairing);
    element_init_G2(pp.a, pairing);
    element_init_G2(pp.B, pairing);
    element_init_G2(pp.d, pairing);

                                                                          
    element_random(pp.g0);
    element_random(pp.g1);
    element_random(pp.W);
    element_random(pp.h);
    element_random(pp.a);
    element_random(pp.B);
    element_random(pp.d);
}

                                                        
void prover_init(ProverSecrets &sec, PublicParams &pp, element_t M, element_t k, element_t r, string id)
{
    element_init_G1(sec.M, pairing);
    element_init_Zr(sec.alpha, pairing);
    element_init_Zr(sec.k, pairing);
    element_init_Zr(sec.gamma, pairing);
    element_init_Zr(sec.u, pairing);

                                                                               
    element_set(sec.M, M);               
    element_random(sec.alpha);               
    element_set(sec.k, k);
    element_invert(sec.gamma, r);
    element_from_hash(sec.u, id.data(), id.size());
}

                                       
void compute_tilde_alpha(element_t &tilde, element_t &alpha, element_t &k, pairing_t &pairing)
{
    element_init_Zr(tilde, pairing);
    element_mul(tilde, alpha, k);                     
}

                                                  
void prover_commit(Commitment &cmt, ProverSecrets &sec, PublicParams &pp, element_t &r_u, element_t &r_k, element_t &r_gamma, element_t &r_alpha, element_t &r_talpha)
{
                          
    element_init_G1(cmt.T1, pairing);
    element_init_G1(cmt.T2, pairing);
    element_init_GT(cmt.R1, pairing);
    element_init_G1(cmt.R2, pairing);
    element_init_G1(cmt.R3, pairing);

                        
    element_t g0_alpha;
    element_init_G1(g0_alpha, pairing);
    element_pow_zn(g0_alpha, pp.g0, sec.alpha);            
    element_mul(cmt.T1, sec.M, g0_alpha);                           

    cout <<"1" << endl;

                    
    element_pow_zn(cmt.T2, pp.g1, sec.alpha);
     cout <<"2" << endl;

                                   
    element_t e_T1_h, e_a_h, e_B_h, e_g0_W, e_g0_h;
    element_init_GT(e_T1_h, pairing);
    element_init_GT(e_a_h, pairing);
    element_init_GT(e_B_h, pairing);
    element_init_GT(e_g0_W, pairing);
    element_init_GT(e_g0_h, pairing);

    pairing_apply(e_T1_h, cmt.T1, pp.h, pairing);            
    pairing_apply(e_a_h, pp.a, pp.h, pairing);              
    pairing_apply(e_B_h, pp.B, pp.h, pairing);              
    pairing_apply(e_g0_W, pp.g0, pp.W, pairing);             
    pairing_apply(e_g0_h, pp.g0, pp.h, pairing);             

                                                                                                             
    element_t tmp;
    element_init_GT(tmp, pairing);
    element_set1(cmt.R1);                  

                    
    element_pow_zn(tmp, e_T1_h, r_k);
    element_invert(tmp, tmp);
    element_mul(cmt.R1, cmt.R1, tmp);

                   
    element_pow_zn(tmp, e_a_h, r_u);
    element_mul(cmt.R1, cmt.R1, tmp);

                       
    element_pow_zn(tmp, e_B_h, r_gamma);
    element_mul(cmt.R1, cmt.R1, tmp);

                        
    element_pow_zn(tmp, e_g0_W, r_alpha);
    element_mul(cmt.R1, cmt.R1, tmp);

                         
    element_pow_zn(tmp, e_g0_h, r_talpha);
    element_mul(cmt.R1, cmt.R1, tmp);

    cout << "3" << endl;

                        
    element_pow_zn(cmt.R2, pp.g1, r_alpha);
        cout << "3.1" << endl;


                                        
    element_t invT2, a1;
    element_init_G1(invT2, pairing);
    element_init_G1(a1, pairing);
        cout << "3.2" << endl;

    element_invert(invT2, cmt.T2);                  
    element_pow_zn(a1, invT2, r_k);                      
        cout << "3.3" << endl;
    
    element_t tmp1;
    element_init_G1(tmp1, pairing);
    element_pow_zn(tmp1, pp.g1, r_talpha);                                                                       
                                                                              
    cout <<"intest" << endl;
    element_t tmpG1;
    element_init_G1(tmpG1, pairing);
    element_pow_zn(tmpG1, pp.g1, r_talpha);
    element_mul(cmt.R3, a1, tmpG1);

    cout << "r" << endl;

                        
    element_clear(g0_alpha);
    element_clear(e_T1_h);
    element_clear(e_a_h);
    element_clear(e_B_h);
    element_clear(e_g0_W);
    element_clear(e_g0_h);
    element_clear(tmp);
    element_clear(invT2);
    element_clear(a1);
    element_clear(tmpG1);
}

                                                                                  
void prover_respond(Response &res, ProverSecrets &sec, element_t &c, element_t &r_u, element_t &r_k, element_t &r_gamma, element_t &r_alpha, element_t &r_talpha, PublicParams &pp)
{
    element_init_Zr(res.su, pairing);
    element_init_Zr(res.s_gamma, pairing);
    element_init_Zr(res.sk, pairing);
    element_init_Zr(res.s_alpha, pairing);
    element_init_Zr(res.s_talpha, pairing);

    element_t tmp;
    element_init_Zr(tmp, pairing);

                       
    element_mul(tmp, c, sec.u);
    element_add(res.su, r_u, tmp);

                                    
    element_mul(tmp, c, sec.gamma);
    element_add(res.s_gamma, r_gamma, tmp);

                       
    element_mul(tmp, c, sec.k);
    element_add(res.sk, r_k, tmp);

                                    
    element_mul(tmp, c, sec.alpha);
    element_add(res.s_alpha, r_alpha, tmp);

                                            
    element_t talpha;
    compute_tilde_alpha(talpha, sec.alpha, sec.k, pairing);
    element_mul(tmp, c, talpha);
    element_add(res.s_talpha, r_talpha, tmp);

    element_clear(tmp);
    element_clear(talpha);
}

                                                  
bool verifier_check(Commitment &cmt, Response &res, element_t &c, PublicParams &pp)
{
    bool ok = true;

                                          
    element_t left1, right1, T2c;
    element_init_G1(left1, pairing);
    element_init_G1(right1, pairing);
    element_init_G1(T2c, pairing);

    element_pow_zn(T2c, cmt.T2, c);                    
    element_mul(left1, cmt.R2, T2c);                        
    element_pow_zn(right1, pp.g1, res.s_alpha);                

    if (element_cmp(left1, right1) != 0)
    {
        cerr << "[VERIFIER] Check1 failed." << endl;
        ok = false;
    }

                                                   
    element_t left2, tmp1, tmp2, invT2;
    element_init_G1(left2, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(invT2, pairing);

    element_invert(invT2, cmt.T2);
    element_pow_zn(tmp1, invT2, res.sk);                      
    element_pow_zn(tmp2, pp.g1, res.s_talpha);                 
    element_mul(left2, tmp1, tmp2);

    if (element_cmp(cmt.R3, left2) != 0)
    {
        cerr << "[VERIFIER] Check2 failed." << endl;
        ok = false;
    }

                                   
                                                                                                                               

                      
    element_t e_T1_W, e_d_h, e_T1_h, e_a_h, e_B_h, e_g0_W, e_g0_h;
    element_init_GT(e_T1_W, pairing);
    element_init_GT(e_d_h, pairing);
    element_init_GT(e_T1_h, pairing);
    element_init_GT(e_a_h, pairing);
    element_init_GT(e_B_h, pairing);
    element_init_GT(e_g0_W, pairing);
    element_init_GT(e_g0_h, pairing);

    pairing_apply(e_T1_W, cmt.T1, pp.W, pairing);            
    pairing_apply(e_d_h, pp.d, pp.h, pairing);              
    pairing_apply(e_T1_h, cmt.T1, pp.h, pairing);            
    pairing_apply(e_a_h, pp.a, pp.h, pairing);             
    pairing_apply(e_B_h, pp.B, pp.h, pairing);             
    pairing_apply(e_g0_W, pp.g0, pp.W, pairing);             
    pairing_apply(e_g0_h, pp.g0, pp.h, pairing);             

                                                      
    element_t ratio, ratio_pow_c, left3;
    element_init_GT(ratio, pairing);
    element_init_GT(ratio_pow_c, pairing);
    element_init_GT(left3, pairing);

    element_invert(e_d_h, e_d_h);                          
    element_mul(ratio, e_T1_W, e_d_h);                          
    element_pow_zn(ratio_pow_c, ratio, c);             
    element_mul(left3, cmt.R1, ratio_pow_c);              

                                                                                                                
    element_t right3, tmpGT;
    element_init_GT(right3, pairing);
    element_init_GT(tmpGT, pairing);

    element_set1(right3);                  

                                                          
    element_pow_zn(tmpGT, e_T1_h, res.sk);
    element_invert(tmpGT, tmpGT);
    element_mul(right3, right3, tmpGT);

                   
    element_pow_zn(tmpGT, e_a_h, res.su);
    element_mul(right3, right3, tmpGT);

                       
    element_pow_zn(tmpGT, e_B_h, res.s_gamma);
    element_mul(right3, right3, tmpGT);

                        
    element_pow_zn(tmpGT, e_g0_W, res.s_alpha);
    element_mul(right3, right3, tmpGT);

                         
    element_pow_zn(tmpGT, e_g0_h, res.s_talpha);
    element_mul(right3, right3, tmpGT);

    if (element_cmp(left3, right3) == 0)
    {
        cerr << "[VERIFIER] Check3 failed." << endl;
        ok = false;
    }

                        
    element_clear(left1);
    element_clear(right1);
    element_clear(T2c);
    element_clear(left2);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(invT2);
    element_clear(e_T1_W);
    element_clear(e_d_h);
    element_clear(e_T1_h);
    element_clear(e_a_h);
    element_clear(e_B_h);
    element_clear(e_g0_W);
    element_clear(e_g0_h);
    element_clear(ratio);
    element_clear(ratio_pow_c);
    element_clear(left3);
    element_clear(right3);
    element_clear(tmpGT);

    return ok;
}


                                                                         
void append_len_and_bytes(vector<unsigned char> &out, const vector<unsigned char> &chunk) {
    uint32_t len = (uint32_t)chunk.size();
    unsigned char lenbe[4];
    lenbe[0] = (unsigned char)((len >> 24) & 0xFF);
    lenbe[1] = (unsigned char)((len >> 16) & 0xFF);
    lenbe[2] = (unsigned char)((len >> 8 ) & 0xFF);
    lenbe[3] = (unsigned char)((len      ) & 0xFF);
    out.insert(out.end(), lenbe, lenbe + 4);
    out.insert(out.end(), chunk.begin(), chunk.end());
}

                                       
vector<unsigned char> generate_sym_key(size_t key_len_bytes) {
    vector<unsigned char> key(key_len_bytes);
    if (RAND_bytes(key.data(), (int)key_len_bytes) != 1) {
        throw runtime_error("RAND_bytes failed");
    }
    return key;
}

                                                     
vector<unsigned char> compute_mac_hmac_sha256(const vector<unsigned char> &key,
                                              element_t NAp, element_t Y, element_t X)
{
                           
    vector<unsigned char> s_z = zr_to_bytes(NAp);            
    vector<unsigned char> s_y = element_to_bytes_vec(Y);                   
    vector<unsigned char> s_x = element_to_bytes_vec(X);                   

                                                                                     
    vector<unsigned char> msg;
    append_len_and_bytes(msg, s_z);
    append_len_and_bytes(msg, s_y);
    append_len_and_bytes(msg, s_x);

                   
    unsigned int outlen = EVP_MD_size(EVP_sha256());
    vector<unsigned char> out(outlen);

    unsigned char *res = HMAC(EVP_sha256(),
                              key.data(), (int)key.size(),
                              msg.data(), msg.size(),
                              out.data(), &outlen);
    if (!res || outlen == 0) throw runtime_error("HMAC failed");
    out.resize(outlen);
    return out;
}

                                         
bool verify_mac_hmac_sha256(const vector<unsigned char> &key,
                            element_t NAp, element_t Y, element_t X,
                            const vector<unsigned char> &mac)
{
    vector<unsigned char> recomputed = compute_mac_hmac_sha256(key, NAp, Y, X);
    if (recomputed.size() != mac.size()) return false;

                               
    unsigned char diff = 0;
    for (size_t i = 0; i < mac.size(); ++i) diff |= (mac[i] ^ recomputed[i]);
    return diff == 0;
}

                                          
string to_hex(const vector<unsigned char> &v) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : v) oss << std::setw(2) << (int)c;
    return oss.str();
}


string bytes_to_hex(const vector<unsigned char> &v)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : v)
        oss << std::setw(2) << (int)c;
    return oss.str();
}

vector<unsigned char> hex_to_bytes(const string &hex) {
    vector<unsigned char> out;
    out.reserve(hex.size()/2);
    for (size_t i=0;i<hex.size(); i+=2) {
        unsigned int b;
        std::istringstream iss(hex.substr(i,2));
        iss >> std::hex >> b;
        out.push_back((unsigned char)b);
    }
    return out;
}

                                                               
vector<unsigned char> generate_hmac_key() {
    vector<unsigned char> key(32);           
    RAND_bytes(key.data(), key.size());
    return key;
}
