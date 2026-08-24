#include <chrono>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>

#include <openssl/rand.h>

#include "CSProtocol.h"
#include "Registration.h"
#include "Login.h"

using namespace std;

struct YangSession
{
    map<string, string> fields;
};

static map<string, YangSession> sessions;
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

static void load_cipher(ElGamalCipher &cipher, const cs::Message &request,
                        const string &prefix)
{
    elgamal_cipher_init(cipher, pairing);
    load_element_blob(cipher.c1, cs::require_field(request, prefix + "_c1"));
    load_element_blob(cipher.c2, cs::require_field(request, prefix + "_c2"));
}

static void load_public_params(PublicParams &pp, const map<string, string> &fields)
{
    element_init_G1(pp.g0, pairing);
    element_init_G1(pp.g1, pairing);
    element_init_G2(pp.W, pairing);
    element_init_G2(pp.h, pairing);
    element_init_G2(pp.a, pairing);
    element_init_G2(pp.B, pairing);
    element_init_G2(pp.d, pairing);
    load_element_blob(pp.g0, fields.at("pp_g0"));
    load_element_blob(pp.g1, fields.at("pp_g1"));
    load_element_blob(pp.W, fields.at("pp_W"));
    load_element_blob(pp.h, fields.at("pp_h"));
    load_element_blob(pp.a, fields.at("pp_a"));
    load_element_blob(pp.B, fields.at("pp_B"));
    load_element_blob(pp.d, fields.at("pp_d"));
}

static void clear_public_params(PublicParams &pp)
{
    element_clear(pp.g0);
    element_clear(pp.g1);
    element_clear(pp.W);
    element_clear(pp.h);
    element_clear(pp.a);
    element_clear(pp.B);
    element_clear(pp.d);
}

static void load_commitment(Commitment &cmt, const map<string, string> &fields)
{
    element_init_G1(cmt.T1, pairing);
    element_init_G1(cmt.T2, pairing);
    element_init_GT(cmt.R1, pairing);
    element_init_G1(cmt.R2, pairing);
    element_init_G1(cmt.R3, pairing);
    load_element_blob(cmt.T1, fields.at("cmt_T1"));
    load_element_blob(cmt.T2, fields.at("cmt_T2"));
    load_element_blob(cmt.R1, fields.at("cmt_R1"));
    load_element_blob(cmt.R2, fields.at("cmt_R2"));
    load_element_blob(cmt.R3, fields.at("cmt_R3"));
}

static void clear_commitment(Commitment &cmt)
{
    element_clear(cmt.T1);
    element_clear(cmt.T2);
    element_clear(cmt.R1);
    element_clear(cmt.R2);
    element_clear(cmt.R3);
}

static cs::Message registration()
{
    const string priv_path = "../Key/bbs_chi.bin";
    const string h_path = "../Key/bbs_h.bin";
    const string W_path = "../Key/bbs_W.bin";
    const string a_path = "../Key/bbs_a.bin";
    const string b_path = "../Key/bbs_b.bin";
    const string d_path = "../Key/bbs_d.bin";
    if (!bbs_keygen(pairing, priv_path, h_path, W_path, a_path, b_path, d_path))
        throw runtime_error("BBS key generation failed");

    BBS_Sign signature;
    signature.init(pairing);
    if (!bbs_sign(pairing, priv_path, a_path, b_path, d_path, h_path, W_path,
                  "hello world", signature))
        throw runtime_error("BBS credential signing failed");

    ElGamalKeypair keypair;
    elgamal_keypair_init(keypair, pairing);
    if (!elgamal_keygen(pairing, keypair, "../Key/elgamal_key"))
        throw runtime_error("ElGamal key generation failed");
    element_t signed_s;
    element_init_G1(signed_s, pairing);
    element_pow_zn(signed_s, g, signature.s);
    ElGamalCipher encrypted_s;
    elgamal_encrypt(pairing, keypair, signed_s, encrypted_s);
    if (!save_elgamal_cipher("../Key/s.bin", encrypted_s))
        throw runtime_error("failed to store encrypted BBS value");

    cs::Message response{"OK", {{"M", element_blob(signature.M)}, {"k", element_blob(signature.k)}}};
    elgamal_cipher_clear(encrypted_s);
    element_clear(signed_s);
    elgamal_keypair_clear(keypair);
    signature.clear();
    return response;
}

static cs::Message login_start()
{
    ElGamalKeypair keypair;
    elgamal_keypair_init(keypair, pairing);
    if (!load_elgamal_keypair("../Key/elgamal_key", keypair))
        throw runtime_error("ElGamal keypair not found; register first");
    ElGamalCipher encrypted_s;
    if (!load_elgamal_cipher("../Key/s.bin", pairing, encrypted_s))
        throw runtime_error("encrypted BBS value not found; register first");
    cs::Message response{"OK", {{"g", element_blob(g)}, {"eg_g", element_blob(keypair.g)}, {"eg_pk", element_blob(keypair.pk)}, {"s_c1", element_blob(encrypted_s.c1)}, {"s_c2", element_blob(encrypted_s.c2)}}};
    elgamal_cipher_clear(encrypted_s);
    elgamal_keypair_clear(keypair);
    return response;
}

static cs::Message login_challenge(const cs::Message &request)
{
    ElGamalKeypair keypair;
    elgamal_keypair_init(keypair, pairing);
    if (!load_elgamal_keypair("../Key/elgamal_key", keypair))
        throw runtime_error("ElGamal keypair not found");
    ElGamalCipher s_star, encrypted_na;
    load_cipher(s_star, request, "sstar");
    load_cipher(encrypted_na, request, "na");

    element_t recovered_s, y, Y, recovered_na, X, NB, challenge;
    element_init_G1(recovered_s, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(Y, pairing);
    element_init_G1(recovered_na, pairing);
    element_init_G1(X, pairing);
    element_init_Zr(NB, pairing);
    element_init_Zr(challenge, pairing);
    elgamal_decrypt(pairing, keypair, s_star, recovered_s);
    elgamal_decrypt(pairing, keypair, encrypted_na, recovered_na);
    load_element_blob(X, cs::require_field(request, "X"));
    element_random(y);
    element_pow_zn(Y, g, y);
    element_random(NB);
    element_random(challenge);

    vector<unsigned char> mac_key = generate_hmac_key();
    vector<unsigned char> mac = compute_mac_hmac_sha256(mac_key, recovered_na, Y, X);
    bool mac_ok = verify_mac_hmac_sha256(mac_key, recovered_na, Y, X, mac);
    if (!mac_ok)
        throw runtime_error("server MAC self-verification failed");

    string token = random_token();
    YangSession session;
    session.fields = request.fields;
    session.fields["y"] = element_blob(y);
    session.fields["Y"] = element_blob(Y);
    session.fields["NB"] = element_blob(NB);
    session.fields["challenge"] = element_blob(challenge);
    sessions[token] = std::move(session);

    cs::Message response{"OK", {{"token", token}, {"Y", element_blob(Y)}, {"NB", element_blob(NB)}, {"challenge", element_blob(challenge)}}};
    elgamal_cipher_clear(s_star);
    elgamal_cipher_clear(encrypted_na);
    elgamal_keypair_clear(keypair);
    element_clear(recovered_s);
    element_clear(y);
    element_clear(Y);
    element_clear(recovered_na);
    element_clear(X);
    element_clear(NB);
    element_clear(challenge);
    return response;
}

static cs::Message login_finish(const cs::Message &request)
{
    string token = cs::require_field(request, "token");
    auto found = sessions.find(token);
    if (found == sessions.end())
        throw runtime_error("unknown or expired login session");
    map<string, string> fields = std::move(found->second.fields);
    sessions.erase(found);

    PublicParams pp;
    Commitment cmt;
    load_public_params(pp, fields);
    load_commitment(cmt, fields);
    Response response;
    element_init_Zr(response.su, pairing);
    element_init_Zr(response.s_gamma, pairing);
    element_init_Zr(response.sk, pairing);
    element_init_Zr(response.s_alpha, pairing);
    element_init_Zr(response.s_talpha, pairing);
    load_element_blob(response.su, cs::require_field(request, "su"));
    load_element_blob(response.s_gamma, cs::require_field(request, "s_gamma"));
    load_element_blob(response.sk, cs::require_field(request, "sk"));
    load_element_blob(response.s_alpha, cs::require_field(request, "s_alpha"));
    load_element_blob(response.s_talpha, cs::require_field(request, "s_talpha"));

    element_t challenge, y, Y, X, NA, NB, shared;
    element_init_Zr(challenge, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(Y, pairing);
    element_init_G1(X, pairing);
    element_init_Zr(NA, pairing);
    element_init_Zr(NB, pairing);
    element_init_G1(shared, pairing);
    load_element_blob(challenge, fields.at("challenge"));
    load_element_blob(y, fields.at("y"));
    load_element_blob(Y, fields.at("Y"));
    load_element_blob(X, fields.at("X"));
    load_element_blob(NA, fields.at("NA_plain"));
    load_element_blob(NB, fields.at("NB"));
    bool proof_ok = verifier_check(cmt, response, challenge, pp);
    element_pow_zn(shared, X, y);
    vector<unsigned char> na_bytes(element_length_in_bytes(NA));
    vector<unsigned char> nb_bytes(element_length_in_bytes(NB));
    element_to_bytes(na_bytes.data(), NA);
    element_to_bytes(nb_bytes.data(), NB);
    vector<unsigned char> key = derive_session_key_H2(na_bytes, nb_bytes, shared);
    cout << "[APAKE Yang Server] Session key: " << bytes_hex(key) << endl;

    clear_public_params(pp);
    clear_commitment(cmt);
    element_clear(response.su);
    element_clear(response.s_gamma);
    element_clear(response.sk);
    element_clear(response.s_alpha);
    element_clear(response.s_talpha);
    element_clear(challenge);
    element_clear(y);
    element_clear(Y);
    element_clear(X);
    element_clear(NA);
    element_clear(NB);
    element_clear(shared);
    return {"OK", {{"authenticated", "1"}, {"proof_ok", proof_ok ? "1" : "0"}}};
}

static cs::Message handle(const cs::Message &request)
{
    if (request.command == "REGISTER")
        return registration();
    if (request.command == "LOGIN_START")
        return login_start();
    if (request.command == "LOGIN_CHALLENGE")
        return login_challenge(request);
    if (request.command == "LOGIN_FINISH")
        return login_finish(request);
    throw runtime_error("unknown command: " + request.command);
}

static void stop_server(int) { running = 0; }

int main(int argc, char **argv)
{
    int port = argc > 1 ? stoi(argv[1]) : 19202;
    sysInitial();
    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    signal(SIGPIPE, SIG_IGN);
    int listener = cs::listen_socket(port);
    cout << "[APAKE Yang Server] Listening on port " << port << " pid=" << getpid() << endl;
    while (running)
    {
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0)
            continue;
        string payload;
        if (cs::recv_frame(fd, payload))
        {
            double elapsed = 0.0;
            try
            {
                cs::Message request = cs::parse_message(payload);
                auto start = chrono::high_resolution_clock::now();
                cs::Message response = handle(request);
                auto end = chrono::high_resolution_clock::now();
                elapsed = chrono::duration<double, milli>(end - start).count();
                response.fields["server_time_ms"] = to_string(elapsed);
                response.fields["server_pid"] = to_string(getpid());
                cs::send_frame(fd, cs::build_message(response.command, response.fields));
                cout << "[APAKE Yang Server] " << request.command << " server_ms=" << elapsed << endl;
            }
            catch (const exception &error)
            {
                cs::send_frame(fd, cs::build_message("ERR", {{"message", error.what()},
                                                             {"server_time_ms", to_string(elapsed)}}));
                cerr << "[APAKE Yang Server] Request failed: " << error.what() << endl;
            }
        }
        close(fd);
    }
    close(listener);
    pairing_clear(pairing);
    return 0;
}
