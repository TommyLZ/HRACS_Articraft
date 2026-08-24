#include <chrono>
#include <cstring>
#include <csignal>
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
using namespace CryptoPP;
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

static bool read_cloud_state(string &stored_id, string &stored_cred, string &s_id, string *r_id)
{
    ifstream in("../Store/Cred_cs.bin", ios::binary);
    if (!in)
        return false;
    readFromBin(in, stored_id);
    readFromBin(in, stored_cred);
    readFromBin(in, s_id);
    if (r_id && in.peek() != EOF)
        readFromBin(in, *r_id);
    return true;
}

static bool credential_matches(const string &id, const string &cred)
{
    string stored_id, stored_cred, s_id;
    return read_cloud_state(stored_id, stored_cred, s_id, nullptr) && stored_id == id && stored_cred == cred;
}

static void require_auth(const cs::Message &msg)
{
    string id = cs::require_field(msg, "id");
    string cred = cs::require_field(msg, "cred_cs");
    if (!credential_matches(id, cred))
        throw runtime_error("cloud server authentication failed");
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
        element_t a, b;
        element_init_G1(a, pairing);
        element_init_G1(b, pairing);
        blob_to_element(a, cs::require_field(msg, "a"));
        keyserver.hardenPassword(b, a, cs::require_field(msg, "id"));
        string b_blob = element_to_blob(b);
        element_clear(a);
        element_clear(b);
        return ok({{"b", b_blob}});
    }

    if (msg.command == "REGISTER")
    {
        string id = cs::require_field(msg, "id");
        string cred_cs = cs::require_field(msg, "cred_cs");
        string cred_ks = cs::require_field(msg, "cred_ks");
        string s_id = cs::require_field(msg, "s_id");
        CloudServer cloudserver;
        KeyServer keyserver;
        cloudserver.store(id, cred_cs, s_id);
        keyserver.store(id, cred_ks);
        return ok({{"registered", "1"}});
    }

    if (msg.command == "CS_GIVE_AUTH")
    {
        string stored_id, stored_cred, s_id, ignored;
        string id = cs::require_field(msg, "id");
        string cred_cs = cs::require_field(msg, "cred_cs");
        string r_id = cs::require_field(msg, "r_id");
        if (!read_cloud_state(stored_id, stored_cred, s_id, &ignored) || stored_id != id || stored_cred != cred_cs)
            throw runtime_error("cloud server authentication failed");
        ofstream out("../Store/Cred_cs.bin", ios::binary);
        writeToBin(out, stored_id);
        writeToBin(out, stored_cred);
        writeToBin(out, s_id);
        writeToBin(out, r_id);
        return ok({{"s_id", s_id}, {"r_id", r_id}});
    }

    if (msg.command == "KS_GIVE_AUTH")
    {
        KeyServer keyserver;
        string id = cs::require_field(msg, "id");
        string t = cs::require_field(msg, "t");
        string ct = cs::require_field(msg, "ct");
        string tag = cs::require_field(msg, "tag");
        keyserver.authenInGive_KS(id, t, ct, tag);
        return ok({{"given", "1"}});
    }

    if (msg.command == "CS_TAKE_AUTH")
    {
        string stored_id, stored_cred, s_id, r_id;
        string id = cs::require_field(msg, "id");
        string cred_cs = cs::require_field(msg, "cred_cs");
        if (!read_cloud_state(stored_id, stored_cred, s_id, &r_id) || stored_id != id || stored_cred != cred_cs)
            throw runtime_error("cloud server authentication failed");
        return ok({{"s_id", s_id}, {"r_id", r_id}});
    }

    if (msg.command == "KS_TAKE_AUTH")
    {
        KeyServer keyserver;
        string ct, tag;
        string id = cs::require_field(msg, "id");
        string t = cs::require_field(msg, "t");
        keyserver.authenInTake_KS(ct, tag, t, id);
        return ok({{"ct", ct}, {"tag", tag}});
    }

    if (msg.command == "UPLOAD")
    {
        require_auth(msg);
        int index = stoi(cs::require_field(msg, "index"));
        store_cipher_and_iv(msg, index);
        return ok({{"count", "1"}, {"uploaded_files", "1"}});
    }

    if (msg.command == "SINGLE_QUERY")
    {
        require_auth(msg);
        int index = stoi(cs::require_field(msg, "index"));
        if (!fs::exists(cipher_path_for(index)) || !fs::exists(iv_path_for(index)))
            throw runtime_error("requested file is not stored on server");
        return ok({{"name", file_prefix(index) + ".dat"},
                   {"cipher", read_binary(cipher_path_for(index))},
                   {"iv", read_binary(iv_path_for(index))}});
    }

    if (msg.command == "UPDATE")
    {
        require_auth(msg);
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
    cout << "[PBCS Server] Listening on port " << port << " pid=" << getpid() << endl;
    cout << "[PBCS Server] Waiting for client requests..." << endl;

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
                cout << "[PBCS Server] >>> Handling " << command << endl;
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
