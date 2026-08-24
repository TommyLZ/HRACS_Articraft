#include "KeyRetrieve.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"
#include "Update.h"
#include "SingleQuery.h"

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

void Update(char *psw_u, char *ID_u, int index)
{
    cout << "**********************************Upload Phase**********************************" << endl;
                                              
                           
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

	char buf[16];
	sprintf(buf, "%03d", index);                      
	std::string filePrefix = "Test_" + std::string(buf);

	              
	std::string cipherDir = "../File/TestMultiple/Cipher";
	std::string recoverDir = "../File/TestMultiple/Recover(Single)";

	std::string cipherPath = cipherDir + "/" + filePrefix + "_cipher.dat";
	std::string ivPath = cipherDir + "/" + filePrefix + ".iv";
	std::string outputPath = recoverDir + "/" + filePrefix + "_recover.dat";

	                           
	if (!fs::exists(cipherPath))
	{
		std::cerr << "Cipher file not found: " << cipherPath << std::endl;
		return;
	}
	if (!fs::exists(ivPath))
	{
		std::cerr << "IV file not found: " << ivPath << std::endl;
		return;
	}

	            
	CryptoPP::byte iv[16 * 16];
	std::ifstream ivFile(ivPath, std::ios::binary);
	ivFile.read(reinterpret_cast<char *>(iv), sizeof(iv));
	ivFile.close();

	               
	aes_EAX_FileDec(cipherPath, key, iv, outputPath);

	std::cout << "Decrypted: " << cipherPath << "  →  " << outputPath << std::endl;

                              
                                       
    std::string plainDir_upt = "../File/Update/Origin";
    std::string cipherDir_upt = "../File/TestMultiple/Cipher(Update)";

                         
    fs::create_directories(cipherDir);

                 
    AutoSeededRandomPool prng;

                                                   
    int fileIndex = 1;

                         
    for (const auto &entry : fs::directory_iterator(plainDir_upt))
    {
        if (!entry.is_regular_file())
            continue;

        fs::path infilePath = entry.path();

                                       
                             
                                       
        char buf[16];
        sprintf(buf, "%03d", fileIndex);                      

        std::string prefix = "Test_" + std::string(buf) + "_cipher";

                       
        std::string outfilePath = cipherDir + "/" + prefix + ".dat";
        std::string ivPath = cipherDir + "/" + prefix + ".iv";

                                       
                                            
                                       
        CryptoPP::byte iv[16 * 16];
        prng.GenerateBlock(iv, sizeof(iv));

                       
        aes_EAX_FileEnc(infilePath.string(), key, iv, outfilePath);

                    
        std::ofstream ivFile(ivPath, std::ios::binary);
        ivFile.write(reinterpret_cast<const char *>(iv), sizeof(iv));
        ivFile.close();

        std::cout << "Update: " << infilePath.string()
                  << " -> " << outfilePath
                  << ", IV saved at " << ivPath << std::endl;

        fileIndex++;             
    }

    std::cout << "All files encrypted successfully!" << std::endl;
}