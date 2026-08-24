#include <chrono>
#include <csignal>
#include <iostream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>

#include <openssl/rand.h>

#include "CSProtocol.h"
#include "Registration.h"
#include "Login.h"

using namespace std;

struct LoginSession
{
    string y;
    string Y;
    string sigma_s;
};

static map<string, LoginSession> sessions;
static volatile sig_atomic_t running = 1;

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

static string random_token()
{
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
        throw runtime_error("RAND_bytes failed");
    static const char hex[] = "0123456789abcdef";
    string token;
    token.reserve(32);
    for (unsigned char byte : bytes)
    {
        token.push_back(hex[byte >> 4]);
        token.push_back(hex[byte & 0x0f]);
    }
    return token;
}

static void load_sdh(element_t server_g, element_t gamma, element_t W)
{
    if (!file_exists(GEN_DIR) || !file_exists(KEY_DIR))
    {
        element_random(server_g);
        element_random(gamma);
        save_to_file(server_g, GEN_DIR);
        save_to_file(gamma, KEY_DIR);
    }
    else
    {
        load_from_file(server_g, GEN_DIR);
        load_from_file(gamma, KEY_DIR);
    }
    element_pow_zn(W, server_g, gamma);
}

static cs::Message registration(const cs::Message &request)
{
    string identity = cs::require_field(request, "identity");
    vector<unsigned char> hash_id(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char *>(identity.data()), identity.size(), hash_id.data());

    element_t m, gamma, W, A, c, s;
    element_init_Zr(m, pairing);
    element_init_Zr(gamma, pairing);
    element_init_G1(W, pairing);
    element_init_G1(A, pairing);
    load_sdh(g, gamma, W);
    element_from_hash(m, hash_id.data(), hash_id.size());
    compute_pbc_mac_sdh(pairing, gamma, m, g, A);
    nizk_prove(pairing, W, m, A, gamma, c, s);
    bool proof_ok = nizk_verify(pairing, W, m, A, c, s);

    cs::Message response{"OK", {{"credential", element_blob(A)}, {"proof_ok", proof_ok ? "1" : "0"}}};
    element_clear(m);
    element_clear(gamma);
    element_clear(W);
    element_clear(A);
    element_clear(c);
    element_clear(s);
    return response;
}

static cs::Message login_start()
{
    element_t server_g, gamma, W, y, Y;
    element_init_G1(server_g, pairing);
    element_init_Zr(gamma, pairing);
    element_init_G1(W, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(Y, pairing);
    load_sdh(server_g, gamma, W);
    do
    {
        element_random(y);
    } while (element_is0(y));
    element_pow_zn(Y, server_g, y);

    vector<unsigned char> Y_bytes(element_length_in_bytes(Y));
    element_to_bytes(Y_bytes.data(), Y);
    EVP_PKEY *private_key = load_or_generate_ecdsa_key();
    if (!private_key)
        throw runtime_error("failed to load server signing key");
    vector<unsigned char> sigma_s;
    if (!sign_message(private_key, Y_bytes, sigma_s))
    {
        EVP_PKEY_free(private_key);
        throw runtime_error("failed to sign server ephemeral key");
    }
    EVP_PKEY_free(private_key);

    string public_pem;
    {
        ifstream input(PUB_KEY_FILE, ios::binary);
        if (!input)
            throw runtime_error("failed to read server public key");
        public_pem.assign(istreambuf_iterator<char>(input), istreambuf_iterator<char>());
    }

    string token = random_token();
    sessions[token] = {element_blob(y), element_blob(Y), vector_blob(sigma_s)};
    cs::Message response{"OK", {{"token", token}, {"g", element_blob(server_g)}, {"W", element_blob(W)}, {"Y", element_blob(Y)}, {"sigma_s", vector_blob(sigma_s)}, {"server_public_key", public_pem}}};
    element_clear(server_g);
    element_clear(gamma);
    element_clear(W);
    element_clear(y);
    element_clear(Y);
    return response;
}

static cs::Message login_finish(const cs::Message &request)
{
    string token = cs::require_field(request, "token");
    auto found = sessions.find(token);
    if (found == sessions.end())
        throw runtime_error("unknown or expired login session");
    LoginSession session = found->second;
    sessions.erase(found);

    element_t server_g, gamma, W, y, Y, X;
    element_init_G1(server_g, pairing);
    element_init_Zr(gamma, pairing);
    element_init_G1(W, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(Y, pairing);
    element_init_G1(X, pairing);
    load_sdh(server_g, gamma, W);
    load_element_blob(y, session.y);
    load_element_blob(Y, session.Y);
    load_element_blob(X, cs::require_field(request, "X"));

    ShowProof proof;
    init_ShowProof(proof, pairing);
    load_element_blob(proof.T, cs::require_field(request, "proof_T"));
    load_element_blob(proof.c, cs::require_field(request, "proof_c"));
    load_element_blob(proof.sm, cs::require_field(request, "proof_sm"));
    load_element_blob(proof.sa, cs::require_field(request, "proof_sa"));

    vector<unsigned char> X_bytes(element_length_in_bytes(X));
    element_to_bytes(X_bytes.data(), X);
    vector<unsigned char> Y_bytes(session.Y.begin(), session.Y.end());
    vector<unsigned char> sigma_s = blob_vector(session.sigma_s);
    vector<unsigned char> label;
    label.insert(label.end(), X_bytes.begin(), X_bytes.end());
    label.insert(label.end(), Y_bytes.begin(), Y_bytes.end());
    label.insert(label.end(), sigma_s.begin(), sigma_s.end());
    bool proof_ok = ShowVerify(proof, pairing, W, gamma, label, server_g);

    vector<unsigned char> proof_bytes;
    serialize_show_proof(proof, pairing, proof_bytes);
    element_t shared;
    element_init_G1(shared, pairing);
    element_pow_zn(shared, X, y);
    vector<unsigned char> server_key = derive_session_key_H2(Y_bytes, sigma_s, X_bytes, proof_bytes, shared);
    cout << "[APAKE Chen Server] Session key: " << bytes_hex(server_key) << endl;

    clear_ShowProof(proof);
    element_clear(server_g);
    element_clear(gamma);
    element_clear(W);
    element_clear(y);
    element_clear(Y);
    element_clear(X);
    element_clear(shared);
    if (!proof_ok)
        throw runtime_error("Show proof verification failed");
    return {"OK", {{"authenticated", "1"}}};
}

static cs::Message handle(const cs::Message &request)
{
    if (request.command == "REGISTER")
        return registration(request);
    if (request.command == "LOGIN_START")
        return login_start();
    if (request.command == "LOGIN_FINISH")
        return login_finish(request);
    throw runtime_error("unknown command: " + request.command);
}

static void stop_server(int) { running = 0; }

int main(int argc, char **argv)
{
    int port = argc > 1 ? stoi(argv[1]) : cs::DEFAULT_PORT;
    sysInitial();
    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    signal(SIGPIPE, SIG_IGN);
    int listener = cs::listen_socket(port);
    cout << "[APAKE Chen Server] Listening on port " << port << " pid=" << getpid() << endl;
    while (running)
    {
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0)
            continue;
        string payload;
        if (cs::recv_frame(fd, payload))
        {
            double server_ms = 0.0;
            try
            {
                cs::Message request = cs::parse_message(payload);
                auto start = chrono::high_resolution_clock::now();
                cs::Message response = handle(request);
                auto end = chrono::high_resolution_clock::now();
                server_ms = chrono::duration<double, milli>(end - start).count();
                response.fields["server_time_ms"] = to_string(server_ms);
                response.fields["server_pid"] = to_string(getpid());
                cs::send_frame(fd, cs::build_message(response.command, response.fields));
                cout << "[APAKE Chen Server] " << request.command << " server_ms=" << server_ms << endl;
            }
            catch (const exception &error)
            {
                cs::send_frame(fd, cs::build_message("ERR", {{"message", error.what()},
                                                             {"server_time_ms", to_string(server_ms)}}));
                cerr << "[APAKE Chen Server] Request failed: " << error.what() << endl;
            }
        }
        close(fd);
    }
    close(listener);
    pairing_clear(pairing);
    return 0;
}
