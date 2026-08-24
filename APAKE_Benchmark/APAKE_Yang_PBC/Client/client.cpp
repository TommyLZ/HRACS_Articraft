#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

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

static vector<unsigned char> blob_vector(const string &value)
{
    return vector<unsigned char>(value.begin(), value.end());
}

static double response_server_ms(const cs::TimedResponse &response)
{
    return stod(cs::require_field(response.message, "server_time_ms"));
}

static void encrypt_to_file(const string &path, const string &password,
                            const vector<unsigned char> &plaintext)
{
    vector<unsigned char> ciphertext, tag, iv;
    if (!encrypt_mac_with_pw(password, plaintext, ciphertext, tag, iv))
        throw runtime_error("credential encryption failed");
    fs::create_directories(fs::path(path).parent_path());
    ofstream output(path, ios::binary);
    if (!output)
        throw runtime_error("cannot write " + path);
    output.write(reinterpret_cast<const char *>(iv.data()), iv.size());
    output.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
    output.write(reinterpret_cast<const char *>(tag.data()), tag.size());
}

static vector<unsigned char> decrypt_from_file(const string &path, const string &password)
{
    ifstream input(path, ios::binary | ios::ate);
    if (!input)
        throw runtime_error("cannot open " + path);
    streamsize size = input.tellg();
    if (size < 28)
        throw runtime_error("credential is truncated: " + path);
    input.seekg(0);
    vector<unsigned char> iv(12), ciphertext(static_cast<size_t>(size - 28)), tag(16);
    input.read(reinterpret_cast<char *>(iv.data()), iv.size());
    input.read(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
    input.read(reinterpret_cast<char *>(tag.data()), tag.size());
    vector<unsigned char> plaintext;
    if (!decrypt_mac_with_pw(password, iv, ciphertext, tag, plaintext))
        throw runtime_error("credential decryption failed: " + path);
    return plaintext;
}

static Metrics register_cs(const string &host, int port, const string &password,
                           const string &identity)
{
    Metrics metrics;
    cs::TimedResponse response = cs::request_timed(host, port, "REGISTER", {{"identity", identity}});
    metrics.server_ms = response_server_ms(response);
    auto start = chrono::high_resolution_clock::now();
    element_t M, k;
    element_init_G1(M, pairing);
    element_init_Zr(k, pairing);
    load_element_blob(M, cs::require_field(response.message, "M"));
    load_element_blob(k, cs::require_field(response.message, "k"));
    encrypt_to_file("../Key/M.bin", password, element_to_bytes_vec(M));
    encrypt_to_file("../Key/k.bin", password, zr_to_bytes(k));
    element_clear(M);
    element_clear(k);
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count();
    return metrics;
}

static Metrics login_cs(const string &host, int port, const string &password,
                        const string &identity)
{
    Metrics metrics;
    cs::TimedResponse first = cs::request_timed(host, port, "LOGIN_START", {{"identity", identity}});
    metrics.server_ms += response_server_ms(first);
    auto local_start_1 = chrono::high_resolution_clock::now();

    element_t server_g, M, k, r, r_group, x, X, NA, na_group;
    element_init_G1(server_g, pairing);
    element_init_G1(M, pairing);
    element_init_Zr(k, pairing);
    element_init_Zr(r, pairing);
    element_init_G1(r_group, pairing);
    element_init_Zr(x, pairing);
    element_init_G1(X, pairing);
    element_init_Zr(NA, pairing);
    element_init_G1(na_group, pairing);
    load_element_blob(server_g, cs::require_field(first.message, "g"));
    vector<unsigned char> M_plain = decrypt_from_file("../Key/M.bin", password);
    vector<unsigned char> k_plain = decrypt_from_file("../Key/k.bin", password);
    element_from_bytes_vec(M, M_plain);
    zr_from_bytes(k, k_plain);

    ElGamalKeypair public_key;
    elgamal_keypair_init(public_key, pairing);
    load_element_blob(public_key.g, cs::require_field(first.message, "eg_g"));
    load_element_blob(public_key.pk, cs::require_field(first.message, "eg_pk"));
    element_set0(public_key.sk);
    ElGamalCipher encrypted_s, encrypted_r, s_star, encrypted_na;
    elgamal_cipher_init(encrypted_s, pairing);
    load_element_blob(encrypted_s.c1, cs::require_field(first.message, "s_c1"));
    load_element_blob(encrypted_s.c2, cs::require_field(first.message, "s_c2"));
    do
    {
        element_random(r);
    } while (element_is0(r));
    element_pow_zn(r_group, public_key.g, r);
    elgamal_encrypt(pairing, public_key, r_group, encrypted_r);
    elgamal_homomorphic_mul(pairing, encrypted_r, encrypted_s, s_star);
    do
    {
        element_random(NA);
    } while (element_is0(NA));
    element_pow_zn(na_group, public_key.g, NA);
    elgamal_encrypt(pairing, public_key, na_group, encrypted_na);
    element_random(x);
    element_pow_zn(X, server_g, x);

    PublicParams pp;
    setup_params(pp);
    ProverSecrets secrets;
    prover_init(secrets, pp, M, k, r, identity);
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
    Commitment cmt;
    prover_commit(cmt, secrets, pp, r_u, r_k, r_gamma, r_alpha, r_talpha);
    auto local_end_1 = chrono::high_resolution_clock::now();

    map<string, string> challenge_fields = {
        {"X", element_blob(X)}, {"NA_plain", element_blob(NA)}, {"sstar_c1", element_blob(s_star.c1)}, {"sstar_c2", element_blob(s_star.c2)}, {"na_c1", element_blob(encrypted_na.c1)}, {"na_c2", element_blob(encrypted_na.c2)}, {"pp_g0", element_blob(pp.g0)}, {"pp_g1", element_blob(pp.g1)}, {"pp_W", element_blob(pp.W)}, {"pp_h", element_blob(pp.h)}, {"pp_a", element_blob(pp.a)}, {"pp_B", element_blob(pp.B)}, {"pp_d", element_blob(pp.d)}, {"cmt_T1", element_blob(cmt.T1)}, {"cmt_T2", element_blob(cmt.T2)}, {"cmt_R1", element_blob(cmt.R1)}, {"cmt_R2", element_blob(cmt.R2)}, {"cmt_R3", element_blob(cmt.R3)}};
    cs::TimedResponse challenge_response = cs::request_timed(host, port, "LOGIN_CHALLENGE", challenge_fields);
    metrics.server_ms += response_server_ms(challenge_response);

    auto local_start_2 = chrono::high_resolution_clock::now();
    element_t challenge, Y, NB;
    element_init_Zr(challenge, pairing);
    element_init_G1(Y, pairing);
    element_init_Zr(NB, pairing);
    load_element_blob(challenge, cs::require_field(challenge_response.message, "challenge"));
    load_element_blob(Y, cs::require_field(challenge_response.message, "Y"));
    load_element_blob(NB, cs::require_field(challenge_response.message, "NB"));
    Response response;
    prover_respond(response, secrets, challenge, r_u, r_k, r_gamma, r_alpha, r_talpha, pp);
    auto local_end_2 = chrono::high_resolution_clock::now();

    cs::TimedResponse finish = cs::request_timed(host, port, "LOGIN_FINISH",
                                                 {{"token", cs::require_field(challenge_response.message, "token")},
                                                  {"su", element_blob(response.su)},
                                                  {"s_gamma", element_blob(response.s_gamma)},
                                                  {"sk", element_blob(response.sk)},
                                                  {"s_alpha", element_blob(response.s_alpha)},
                                                  {"s_talpha", element_blob(response.s_talpha)}});
    metrics.server_ms += response_server_ms(finish);

    auto local_start_3 = chrono::high_resolution_clock::now();
    element_t shared;
    element_init_G1(shared, pairing);
    element_pow_zn(shared, Y, x);
    vector<unsigned char> na_bytes(element_length_in_bytes(NA));
    vector<unsigned char> nb_bytes(element_length_in_bytes(NB));
    element_to_bytes(na_bytes.data(), NA);
    element_to_bytes(nb_bytes.data(), NB);
    vector<unsigned char> key = derive_session_key_H2(na_bytes, nb_bytes, shared);
    cout << "[APAKE Yang Client] Session key: " << bytes_to_hex(key) << endl;
    auto local_end_3 = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(local_end_1 - local_start_1).count() +
                        chrono::duration<double, milli>(local_end_2 - local_start_2).count() +
                        chrono::duration<double, milli>(local_end_3 - local_start_3).count();

    element_clear(server_g);
    element_clear(M);
    element_clear(k);
    element_clear(r);
    element_clear(r_group);
    element_clear(x);
    element_clear(X);
    element_clear(NA);
    element_clear(na_group);
    elgamal_keypair_clear(public_key);
    elgamal_cipher_clear(encrypted_s);
    elgamal_cipher_clear(encrypted_r);
    elgamal_cipher_clear(s_star);
    elgamal_cipher_clear(encrypted_na);
    element_clear(r_u);
    element_clear(r_k);
    element_clear(r_gamma);
    element_clear(r_alpha);
    element_clear(r_talpha);
    element_clear(secrets.M);
    element_clear(secrets.alpha);
    element_clear(secrets.k);
    element_clear(secrets.gamma);
    element_clear(secrets.u);
    element_clear(cmt.T1);
    element_clear(cmt.T2);
    element_clear(cmt.R1);
    element_clear(cmt.R2);
    element_clear(cmt.R3);
    element_clear(response.su);
    element_clear(response.s_gamma);
    element_clear(response.sk);
    element_clear(response.s_alpha);
    element_clear(response.s_talpha);
    element_clear(pp.g0);
    element_clear(pp.g1);
    element_clear(pp.W);
    element_clear(pp.h);
    element_clear(pp.a);
    element_clear(pp.B);
    element_clear(pp.d);
    element_clear(challenge);
    element_clear(Y);
    element_clear(NB);
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
    int port = argc > 2 ? stoi(argv[2]) : 19202;
    string identity = argc > 3 ? argv[3] : "15926254568";
    string password = argc > 4 ? argv[4] : "19880532Tom";
    int iterations = argc > 5 ? stoi(argv[5]) : 5;
    if (iterations < 1)
        throw runtime_error("iterations must be positive");
    sysInitial();
    Metrics registration_total, login_total;
    for (int i = 0; i < iterations; ++i)
    {
        cout << "[APAKE Yang Client] Iteration " << (i + 1) << '/' << iterations << endl;
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
    string path = "../Result/" + date_stamp() + "_APAKE_Yang.csv";
    ofstream csv(path);
    csv << "module,client_ms,server_ms\n"
        << fixed << setprecision(6);
    csv << "Registration," << registration_total.client_ms << ',' << registration_total.server_ms << '\n';
    csv << "Login," << login_total.client_ms << ',' << login_total.server_ms << '\n';
    cout << "[APAKE Yang Client] CSV written to " << path << endl;
    pairing_clear(pairing);
    return 0;
}
