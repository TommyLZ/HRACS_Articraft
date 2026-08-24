#include "Take.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"
#include "BatchQuery.h"

#include <iostream>
#include <fstream>
#include <cryptopp/osrng.h>
#include <filesystem>
using namespace std;

extern pairing_t pairing;

namespace fs = std::filesystem;

void BatchQuery(string &psw, string &id, vector<int> indexList)
{
    cout << "**********************************BatchQuery phase**********************************" << endl;

    Client client(psw, id);
    KeyServer keyserver;
    CloudServer cloudserver;

    element_t a;
    element_init_G1(a, pairing);
    client.blindPassword(a);
    cout << "The client blinds the password and sends it to the key server!" << endl;

    element_t b;
    element_init_G1(b, pairing);
    keyserver.hardenPassword(b, a, id);
    cout << "Password Hardening Finished!" << endl;

    string cred_cs;
    client.pwdGen(b, cred_cs);
    cout << "The client ready to log in the cloud server!" << endl;

    string s_id;
    string r_id;
    cloudserver.authenInTake_CS(s_id, r_id, id, cred_cs);
    cout << "You have successfully logged in the cloud server!" << endl;

    string t;
    string k_1;
    string k_2;
    client.loginToKS_Take(t, k_1, k_2, s_id, r_id);
    cout << "The client ready to log in the key server!" << endl;

    string ct;
    string tag;
    keyserver.authenInTake_KS(ct, tag, t, id);
    cout << "You have successfully logged in the key server!" << endl;

    string mk;
    client.recover(mk, k_1, k_2, ct, tag);
    cout << "The key recovery is finished!" << endl;

    CryptoPP::byte key[16];
    std::memcpy(key, mk.data(), 16);

    std::string cipherDir = "../File/TestMultiple/Cipher";
    std::string recoverDir = "../File/TestMultiple/Recover(Batch)";

    fs::create_directories(recoverDir);

    for (int index : indexList)
    {
        char buf[16];
        sprintf(buf, "%03d", index);

        std::string prefix = "Test_" + std::string(buf);

        std::string cipherPath = cipherDir + "/" + prefix + "_cipher.dat";
        std::string ivPath = cipherDir + "/" + prefix + ".iv";
        std::string outPath = recoverDir + "/" + prefix + "_recover.dat";

        if (!fs::exists(cipherPath))
        {
            std::cout << "⚠️ Cipher not found: " << cipherPath << endl;
            continue;
        }
        if (!fs::exists(ivPath))
        {
            std::cout << "⚠️ IV not found: " << ivPath << endl;
            continue;
        }

        CryptoPP::byte iv[16 * 16];
        std::ifstream ivFile(ivPath, std::ios::binary);
        ivFile.read(reinterpret_cast<char *>(iv), sizeof(iv));
        ivFile.close();

        aes_EAX_FileDec(cipherPath, key, iv, outPath);

        std::cout << "✔️ Decrypted: " << cipherPath
                  << " -> " << outPath << endl;
    }

    cout << "BatchQuery Finished!" << endl;
}