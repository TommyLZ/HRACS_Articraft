#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <unistd.h>

#include "CSProtocol.h"
#include "CloudServer.h"
#include "KeyServer.h"
#include "PublicParam.h"

using namespace std;
namespace fs = std::filesystem;

extern pairing_t pairing;

static bool running = true;

static string element_to_blob(element_t e)
{
    int len = element_length_in_bytes(e);
    string out(len, '\0');
    element_to_bytes(reinterpret_cast<unsigned char *>(out.data()), e);
    return out;
}

static void blob_to_element(element_t e, const string &blob)
{
    element_from_bytes(e, reinterpret_cast<unsigned char *>(const_cast<char *>(blob.data())));
}

static string read_binary(const fs::path &path)
{
    ifstream in(path, ios::binary);
    if (!in)
        throw runtime_error("failed to read " + path.string());
    return string((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
}

static void write_binary(const fs::path &path, const string &data)
{
    fs::create_directories(path.parent_path());
    ofstream out(path, ios::binary);
    if (!out)
        throw runtime_error("failed to write " + path.string());
    out.write(data.data(), static_cast<streamsize>(data.size()));
}

static string file_prefix(int index)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%03d", index);
    return "Test_" + string(buf);
}

static fs::path cipher_path_for(int index)
{
    return fs::path("../File/TestMultiple/Cipher") / (file_prefix(index) + "_cipher.dat");
}

static fs::path iv_path_for(int index)
{
    return fs::path("../File/TestMultiple/Cipher") / (file_prefix(index) + ".iv");
}

static cs::Message ok(map<string, string> fields)
{
    return {"OK", std::move(fields)};
}

static void store_cipher_and_iv(const cs::Message &msg, int index)
{
    string cipher = cs::require_field(msg, "cipher");
    string iv = cs::require_field(msg, "iv");
    if (cipher.empty())
        throw runtime_error("empty cipher upload for index " + to_string(index));
    if (iv.size() != 16 * 16)
        throw runtime_error("invalid IV upload for index " + to_string(index) + ": " + to_string(iv.size()) + " bytes");
    write_binary(cipher_path_for(index), cipher);
    write_binary(iv_path_for(index), iv);
}

static cs::Message handle(const cs::Message &msg)
{
    if (msg.command == "HARDEN")
    {
        KeyServer keyserver;
        string id = cs::require_field(msg, "id");
        element_t alpha, beta;
        element_init_G1(alpha, pairing);
        element_init_G1(beta, pairing);
        blob_to_element(alpha, cs::require_field(msg, "alpha"));
        keyserver.hardenPassword(beta, alpha, id.data());
        string beta_blob = element_to_blob(beta);
        string public_key = element_to_blob(keyserver.public_key);
        element_clear(alpha);
        element_clear(beta);
        return ok({{"beta", beta_blob}, {"public_key", public_key}});
    }

    if (msg.command == "REGISTER")
    {
        string id = cs::require_field(msg, "id");
        string cred_cs = cs::require_field(msg, "cred_cs");
        string cred_ks = cs::require_field(msg, "cred_ks");
        string s_u = cs::require_field(msg, "s_u");
        CloudServer cloudserver;
        KeyServer keyserver;
        cloudserver.store(id.data(), cred_cs, s_u);
        keyserver.store(id.data(), cred_ks);
        return ok({{"registered", "1"}});
    }

    if (msg.command == "CS_GEN_AUTH")
    {
        string id = cs::require_field(msg, "id");
        string EM_CS = cs::require_field(msg, "EM_CS");
        string iv_blob = cs::require_field(msg, "iv");
        if (iv_blob.size() != 16)
            throw runtime_error("invalid CS auth IV size");
        CryptoPP::byte iv[16];
        memcpy(iv, iv_blob.data(), sizeof(iv));
        string s_u;
        CloudServer cloudserver;
        cloudserver.authenInGen_CS(s_u, id.data(), EM_CS, iv);
        return ok({{"s_u", s_u}});
    }

    if (msg.command == "KS_GEN_AUTH")
    {
        string EM_KS = cs::require_field(msg, "EM_KS");
        string iv_blob = cs::require_field(msg, "iv");
        if (iv_blob.size() != 16)
            throw runtime_error("invalid KS auth IV size");
        CryptoPP::byte iv[16];
        memcpy(iv, iv_blob.data(), sizeof(iv));
        string ctx_sk = cs::require_field(msg, "ctx_sk");
        string rho_u = cs::require_field(msg, "rho_u");
        KeyServer keyserver;
        keyserver.authenInGen_KS(EM_KS, ctx_sk, rho_u, iv);
        return ok({{"stored", "1"}});
    }

    if (msg.command == "CS_RANDOM_STORE")
    {
        string gamma_u = cs::require_field(msg, "gamma_u");
        CloudServer cloudserver;
        cloudserver.randomStore(gamma_u);
        return ok({{"stored", "1"}});
    }

    if (msg.command == "CS_RETRIEVE_AUTH")
    {
        string id = cs::require_field(msg, "id");
        string EM_CS = cs::require_field(msg, "EM_CS");
        string iv_blob = cs::require_field(msg, "iv");
        if (iv_blob.size() != 16)
            throw runtime_error("invalid CS retrieve IV size");
        CryptoPP::byte iv[16];
        memcpy(iv, iv_blob.data(), sizeof(iv));
        string s_u, gamma_u;
        CloudServer cloudserver;
        cloudserver.authenInRetrieve_CS(s_u, gamma_u, id.data(), EM_CS, iv);
        return ok({{"s_u", s_u}, {"gamma_u", gamma_u}});
    }

    if (msg.command == "KS_RETRIEVE_AUTH")
    {
        string EM_KS = cs::require_field(msg, "EM_KS");
        string iv_blob = cs::require_field(msg, "iv");
        if (iv_blob.size() != 16)
            throw runtime_error("invalid KS retrieve IV size");
        CryptoPP::byte iv[16];
        memcpy(iv, iv_blob.data(), sizeof(iv));
        string ctx_sk, rho_u;
        KeyServer keyserver;
        keyserver.authenInRetrieve_KS(ctx_sk, rho_u, EM_KS, iv);
        return ok({{"ctx_sk", ctx_sk}, {"rho_u", rho_u}});
    }

    if (msg.command == "UPLOAD")
    {
        int index = stoi(cs::require_field(msg, "index"));
        store_cipher_and_iv(msg, index);
        return ok({{"count", "1"}, {"uploaded_files", "1"}});
    }

    if (msg.command == "SINGLE_QUERY")
    {
        int index = stoi(cs::require_field(msg, "index"));
        if (!fs::exists(cipher_path_for(index)) || !fs::exists(iv_path_for(index)))
            throw runtime_error("requested file is not stored on server");
        return ok({{"name", file_prefix(index) + ".dat"},
                   {"cipher", read_binary(cipher_path_for(index))},
                   {"iv", read_binary(iv_path_for(index))}});
    }

    if (msg.command == "UPDATE")
    {
        int index = stoi(cs::require_field(msg, "index"));
        store_cipher_and_iv(msg, index);
        return ok({{"updated", "1"}, {"updated_files", "1"}});
    }

    throw runtime_error("unknown command: " + msg.command);
}

static void handle_signal(int)
{
    running = false;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? stoi(argv[1]) : cs::DEFAULT_PORT;
    sysInitial();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    int listener = cs::listen_socket(port);
    cout << "[IPBCS Server] Listening on port " << port << " pid=" << getpid() << endl;
    cout << "[IPBCS Server] Waiting for client requests..." << endl;

    while (running)
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int fd = accept(listener, reinterpret_cast<sockaddr *>(&client_addr), &client_len);
        if (fd < 0)
            continue;

        string command = "UNKNOWN";
        size_t request_bytes = 0;
        size_t response_bytes = 0;
        double server_ms = 0.0;
        string payload;
        if (cs::recv_frame(fd, payload))
        {
            try
            {
                request_bytes = payload.size() + sizeof(uint32_t);
                cs::Message request = cs::parse_message(payload);
                command = request.command;
                cout << "[IPBCS Server] >>> Handling " << command << endl;
                auto start = chrono::high_resolution_clock::now();
                cs::Message response = handle(request);
                auto end = chrono::high_resolution_clock::now();
                server_ms = chrono::duration<double, milli>(end - start).count();
                response.fields["server_time_ms"] = to_string(server_ms);
                response.fields["server_pid"] = to_string(getpid());
                string response_payload = cs::build_message(response.command, response.fields);
                response_bytes = response_payload.size() + sizeof(uint32_t);
                cs::send_frame(fd, response_payload);
            }
            catch (const exception &ex)
            {
                string response_payload = cs::build_message("ERR", {{"message", ex.what()}, {"server_time_ms", to_string(server_ms)}, {"server_pid", to_string(getpid())}});
                response_bytes = response_payload.size() + sizeof(uint32_t);
                cs::send_frame(fd, response_payload);
                cerr << "Request failed: " << ex.what() << endl;
            }
        }

        cout << "[Server Metrics] module=" << command
             << " pid=" << getpid()
             << " server_time_ms=" << server_ms
             << " request_bytes=" << request_bytes
             << " response_bytes=" << response_bytes
             << " communication_overhead_bytes=" << (request_bytes + response_bytes)
             << endl;
        close(fd);
    }
    close(listener);
    return 0;
}
