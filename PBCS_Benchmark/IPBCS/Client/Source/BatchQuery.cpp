#include "KeyRetrieve.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"
#include "BatchQuery.h"

#include <iostream>
#include <chrono>
#include <cryptopp/osrng.h>
#include <pbc/pbc.h>
#include <filesystem>
#include <fstream>

extern pairing_t pairing;

using namespace std;
using namespace CryptoPP;

namespace fs = std::filesystem;

void BatchQuery(char *psw_u, char *ID_u, const std::vector<int> &indexList)
{
    cout << "**********************************BatchQuery Phase**********************************" << endl;

                                           
    Client client(psw_u, ID_u);
    KeyServer keyserver;
    CloudServer cloudserver;

                            
    element_t alpha;
    element_init_G1(alpha, pairing);
    client.blindPassword(alpha);

                            
    element_t beta;
    element_init_G1(beta, pairing);
    keyserver.hardenPassword(beta, alpha, ID_u);
    cout << "Password Hardening Finished!" << endl;

                            
    string psw_u_hat;
    string EM_CS;
    AutoSeededRandomPool prng_CS;
    CryptoPP::byte iv_CS[16];
    prng_CS.GenerateBlock(iv_CS, 16);

    client.loginToCS(psw_u_hat, EM_CS, iv_CS, alpha, beta, keyserver.public_key);
    cout << "The client ready to log in the cloud server!" << endl;

    string s_u;
    string gamma_u;
    cloudserver.authenInRetrieve_CS(s_u, gamma_u, client.getID(), EM_CS, iv_CS);
    cout << "You have successfully logged in the cloud server!" << endl;

                          
    string EM_KS;
    AutoSeededRandomPool prng_KS;
    CryptoPP::byte iv_KS[16];
    prng_KS.GenerateBlock(iv_KS, 16);

    client.loginToKS(psw_u_hat, s_u, EM_KS, iv_KS);
    cout << "The client ready to log in the key server!" << endl;

    string ctx_dsk;
    string rho_u;
    keyserver.authenInRetrieve_KS(ctx_dsk, rho_u, EM_KS, iv_KS);
    cout << "You have successfully logged in the key server!" << endl;

                   
    string sk;
    client.retrieval(sk, gamma_u, psw_u_hat, ctx_dsk, rho_u);
    cout << "The key retrieval is finished!" << endl;

                      
    CryptoPP::byte key[16];
    std::memcpy(key, sk.data(), 16);

                                   
                    
                                   
    std::string cipherDir = "../File/TestMultiple/Cipher";
    std::string recoverDir = "../File/TestMultiple/Recover(Batch)";

    fs::create_directories(recoverDir);

                                   
                                  
                                   
    for (int index : indexList)
    {
        char buf[16];
        sprintf(buf, "%03d", index);                       

        std::string prefix = "Test_" + std::string(buf);

        std::string cipherPath = cipherDir + "/" + prefix + "_cipher.dat";
        std::string ivPath     = cipherDir + "/" + prefix + ".iv";
        std::string outPath    = recoverDir + "/" + prefix + "_recover.dat";

                                   
        if (!fs::exists(cipherPath)) {
            std::cout << "⚠️ Cipher not found: " << cipherPath << endl;
            continue;
        }
        if (!fs::exists(ivPath)) {
            std::cout << "⚠️ IV not found: " << ivPath << endl;
            continue;
        }

                    
        CryptoPP::byte iv[16 * 16];
        std::ifstream ivFile(ivPath, std::ios::binary);
        ivFile.read(reinterpret_cast<char*>(iv), sizeof(iv));
        ivFile.close();

                 
        aes_EAX_FileDec(cipherPath, key, iv, outPath);

        std::cout << "✔️ Decrypted: " << cipherPath
                  << " -> " << outPath << endl;
    }

    cout << "BatchQuery Finished!" << endl;
}
