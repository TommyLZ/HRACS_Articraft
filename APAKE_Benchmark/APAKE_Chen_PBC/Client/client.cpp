#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/pem.h>

#include "CSProtocol.h"
#include "Registration.h"
#include "Login.h"

using namespace std;
namespace fs = std::filesystem;

struct Metrics
{
    double client_ms = 0.0;
    double server_ms = 0.0;
};

static string element_blob(element_t value)
{
    string out(element_length_in_bytes(value), '\0');
    element_to_bytes(reinterpret_cast<unsigned char *>(out.data()), value);
    return out;
}

static void load_element_blob(element_t value, const string &blob)
{
    if (blob.empty())
        throw runtime_error("empty PBC element");
    element_from_bytes(value, reinterpret_cast<unsigned char *>(const_cast<char *>(blob.data())));
}

static string vector_blob(const vector<unsigned char> &value)
{
    return string(reinterpret_cast<const char *>(value.data()), value.size());
}

static vector<unsigned char> blob_vector(const string &value)
{
    return vector<unsigned char>(value.begin(), value.end());
}

static string bytes_hex(const vector<unsigned char> &value)
{
    ostringstream out;
    out << hex << setfill('0');
    for (unsigned char byte : value)
        out << setw(2) << static_cast<int>(byte);
    return out.str();
}

static double server_ms(const cs::TimedResponse &response)
{
    return stod(cs::require_field(response.message, "server_time_ms"));
}

static EVP_PKEY *public_key_from_pem(const string &pem)
{
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio)
        return nullptr;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;
}

static void store_credential(const string &password, const string &identity,
                             const string &credential_blob)
{
    vector<unsigned char> plaintext = blob_vector(credential_blob);
    vector<unsigned char> ciphertext, tag, iv;
    if (!encrypt_mac_with_pw(password, plaintext, ciphertext, tag, iv))
        throw runtime_error("credential encryption failed");
    fs::create_directories("../Key");
    ofstream output("../Key/" + identity + "_cred.bin", ios::binary);
    if (!output)
        throw runtime_error("cannot write local credential");
    output.write(reinterpret_cast<const char *>(iv.data()), iv.size());
    output.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
    output.write(reinterpret_cast<const char *>(tag.data()), tag.size());
}

static vector<unsigned char> load_credential(const string &password, const string &identity)
{
    ifstream input("../Key/" + identity + "_cred.bin", ios::binary | ios::ate);
    if (!input)
        throw runtime_error("cannot open local credential");
    streamsize size = input.tellg();
    if (size < 28)
        throw runtime_error("local credential is truncated");
    input.seekg(0);
    vector<unsigned char> iv(12), ciphertext(static_cast<size_t>(size - 28)), tag(16);
    input.read(reinterpret_cast<char *>(iv.data()), iv.size());
    input.read(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
    input.read(reinterpret_cast<char *>(tag.data()), tag.size());
    vector<unsigned char> plaintext;
    if (!decrypt_mac_with_pw(password, iv, ciphertext, tag, plaintext))
        throw runtime_error("credential decryption failed");
    return plaintext;
}

static Metrics register_cs(const string &host, int port, const string &password,
                           const string &identity)
{
    Metrics metrics;
    cs::TimedResponse response = cs::request_timed(host, port, "REGISTER", {{"identity", identity}});
    metrics.server_ms = server_ms(response);
    auto start = chrono::high_resolution_clock::now();
    store_credential(password, identity, cs::require_field(response.message, "credential"));
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count();
    return metrics;
}

static Metrics login_cs(const string &host, int port, const string &password,
                        const string &identity)
{
    Metrics metrics;
    cs::TimedResponse first = cs::request_timed(host, port, "LOGIN_START", {{"identity", identity}});
    metrics.server_ms += server_ms(first);

    auto local_start = chrono::high_resolution_clock::now();
    element_t server_g, W, Y, m, A, x, X;
    element_init_G1(server_g, pairing);
    element_init_G1(W, pairing);
    element_init_G1(Y, pairing);
    element_init_Zr(m, pairing);
    element_init_G1(A, pairing);
    element_init_Zr(x, pairing);
    element_init_G1(X, pairing);
    load_element_blob(server_g, cs::require_field(first.message, "g"));
    load_element_blob(W, cs::require_field(first.message, "W"));
    load_element_blob(Y, cs::require_field(first.message, "Y"));
    vector<unsigned char> sigma_s = blob_vector(cs::require_field(first.message, "sigma_s"));

    vector<unsigned char> Y_bytes(element_length_in_bytes(Y));
    element_to_bytes(Y_bytes.data(), Y);
    EVP_PKEY *public_key = public_key_from_pem(cs::require_field(first.message, "server_public_key"));
    if (!public_key || !verify_signature(public_key, Y_bytes, sigma_s))
    {
        if (public_key)
            EVP_PKEY_free(public_key);
        throw runtime_error("server signature verification failed");
    }
    EVP_PKEY_free(public_key);

    unsigned char id_hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(identity.data()), identity.size(), id_hash);
    element_from_hash(m, id_hash, sizeof(id_hash));
    vector<unsigned char> credential = load_credential(password, identity);
    element_from_bytes(A, credential.data());
    do
    {
        element_random(x);
    } while (element_is0(x));
    element_pow_zn(X, server_g, x);
    vector<unsigned char> X_bytes(element_length_in_bytes(X));
    element_to_bytes(X_bytes.data(), X);
    vector<unsigned char> label;
    label.insert(label.end(), X_bytes.begin(), X_bytes.end());
    label.insert(label.end(), Y_bytes.begin(), Y_bytes.end());
    label.insert(label.end(), sigma_s.begin(), sigma_s.end());
    ShowProof proof;
    init_ShowProof(proof, pairing);
    Show(proof, pairing, A, m, label, server_g);
    auto local_middle = chrono::high_resolution_clock::now();

    cs::TimedResponse second = cs::request_timed(host, port, "LOGIN_FINISH",
                                                 {{"token", cs::require_field(first.message, "token")},
                                                  {"X", element_blob(X)},
                                                  {"proof_T", element_blob(proof.T)},
                                                  {"proof_c", element_blob(proof.c)},
                                                  {"proof_sm", element_blob(proof.sm)},
                                                  {"proof_sa", element_blob(proof.sa)}});
    metrics.server_ms += server_ms(second);

    auto local_resume = chrono::high_resolution_clock::now();
    vector<unsigned char> proof_bytes;
    serialize_show_proof(proof, pairing, proof_bytes);
    element_t shared;
    element_init_G1(shared, pairing);
    element_pow_zn(shared, Y, x);
    vector<unsigned char> client_key = derive_session_key_H2(Y_bytes, sigma_s, X_bytes, proof_bytes, shared);
    cout << "[APAKE Chen Client] Session key: " << bytes_hex(client_key) << endl;
    auto local_end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(local_middle - local_start).count() +
                        chrono::duration<double, milli>(local_end - local_resume).count();

    clear_ShowProof(proof);
    element_clear(server_g);
    element_clear(W);
    element_clear(Y);
    element_clear(m);
    element_clear(A);
    element_clear(x);
    element_clear(X);
    element_clear(shared);
    return metrics;
}

static string date_stamp()
{
    time_t now = time(nullptr);
    tm local{};
    localtime_r(&now, &local);
    char buffer[16];
    strftime(buffer, sizeof(buffer), "%Y%m%d", &local);
    return buffer;
}

int main(int argc, char **argv)
{
    string host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? stoi(argv[2]) : cs::DEFAULT_PORT;
    string identity = argc > 3 ? argv[3] : "15926254568";
    string password = argc > 4 ? argv[4] : "19880532Tom";
    int iterations = argc > 5 ? stoi(argv[5]) : 5;
    if (iterations < 1)
        throw runtime_error("iterations must be positive");
    sysInitial();

    Metrics registration_total, login_total;
    for (int i = 0; i < iterations; ++i)
    {
        cout << "[APAKE Chen Client] Iteration " << (i + 1) << '/' << iterations << endl;
        Metrics registration = register_cs(host, port, password, identity);
        Metrics login = login_cs(host, port, password, identity);
        registration_total.client_ms += registration.client_ms;
        registration_total.server_ms += registration.server_ms;
        login_total.client_ms += login.client_ms;
        login_total.server_ms += login.server_ms;
    }
    registration_total.client_ms /= iterations;
    registration_total.server_ms /= iterations;
    login_total.client_ms /= iterations;
    login_total.server_ms /= iterations;

    fs::create_directories("../Result");
    string path = "../Result/" + date_stamp() + "_APAKE_Chen.csv";
    ofstream csv(path);
    csv << "module,client_ms,server_ms\n"
        << fixed << setprecision(6);
    csv << "Registration," << registration_total.client_ms << ',' << registration_total.server_ms << '\n';
    csv << "Login," << login_total.client_ms << ',' << login_total.server_ms << '\n';
    cout << "[APAKE Chen Client] CSV written to " << path << endl;
    pairing_clear(pairing);
    return 0;
}
