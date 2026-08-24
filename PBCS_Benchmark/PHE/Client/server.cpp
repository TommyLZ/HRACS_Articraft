#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <unistd.h>

#include <cryptopp/osrng.h>

#include "CSProtocol.h"
#include "CloudServer.h"
#include "KeyServer.h"
#include "PublicParam.h"

using namespace std;
using namespace CryptoPP;
namespace fs = std::filesystem;

extern pairing_t pairing;
extern element_t g;

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

static fs::path plain_path_for(int index)
{
    return fs::path("../File/ServerUpload/Plain") / (file_prefix(index) + ".dat");
}

static fs::path cipher_path_for(int index)
{
    return fs::path("../File/TestMultiple/Cipher") / (file_prefix(index) + "_cipher.dat");
}

static fs::path iv_path_for(int index)
{
    return fs::path("../File/TestMultiple/Cipher") / (file_prefix(index) + ".iv");
}

static fs::path recover_path_for(const string &kind, int index)
{
    return fs::path("../File/TestMultiple") / kind / (file_prefix(index) + "_recover.dat");
}

static cs::Message ok(map<string, string> fields)
{
    return {"OK", std::move(fields)};
}

static bool credential_matches(const string &id, const string &cred)
{
    ifstream in("../Store/Cred_cs.bin", ios::binary);
    if (!in)
        return false;
    string stored_id, stored_cred;
    readFromBin(in, stored_id);
    readFromBin(in, stored_cred);
    return stored_id == id && stored_cred == cred;
}

static void require_auth(const cs::Message &msg)
{
    string id = cs::require_field(msg, "id");
    string cred = cs::require_field(msg, "cred_cs");
    if (!credential_matches(id, cred))
        throw runtime_error("cloud server authentication failed");
}

static void recover_original_mk(const string &cred_cs, element_t &mk)
{
    KeyServer keyserver;
    CloudServer cloudserver;
    element_t c0, c1, hr1, hs1;
    element_init_G1(c0, pairing);
    element_init_G1(c1, pairing);
    element_init_G1(hr1, pairing);
    element_init_G1(hs1, pairing);

    string cred = cred_cs;
    cloudserver.decrypt(c0, cred, hr1, hs1);
    keyserver.decrypt(c1, c0);
    cloudserver.key_Recover(mk, c1, hr1, hs1, keyserver.public_key);

    element_clear(c0);
    element_clear(c1);
    element_clear(hr1);
    element_clear(hs1);
}

static void original_file_encrypt_with_mk(element_t &mk, int index, const string &plain)
{
    write_binary(plain_path_for(index), plain);
    fs::create_directories(cipher_path_for(index).parent_path());

    AutoSeededRandomPool prng;
    CryptoPP::byte iv[16 * 16];
    prng.GenerateBlock(iv, sizeof(iv));

    CloudServer cloudserver;
    string in = plain_path_for(index).string();
    string out = cipher_path_for(index).string();
    string ivfile = iv_path_for(index).string();
    cloudserver.fileEncryption(mk, iv, in, out, ivfile);
}

static string original_file_decrypt_with_mk(element_t &mk, int index, const string &kind)
{
    if (!fs::exists(cipher_path_for(index)) || !fs::exists(iv_path_for(index)))
        throw runtime_error("requested file is not stored on server");

    CryptoPP::byte iv[16 * 16]{};
    ifstream iv_file(iv_path_for(index), ios::binary);
    if (!iv_file)
        throw runtime_error("failed to read IV");
    iv_file.read(reinterpret_cast<char *>(iv), sizeof(iv));

    fs::path recover_path = recover_path_for(kind, index);
    fs::create_directories(recover_path.parent_path());
    CloudServer cloudserver;
    string in = cipher_path_for(index).string();
    string out = recover_path.string();
    cloudserver.fileDecryption(mk, iv, in, out);
    return read_binary(recover_path);
}

static cs::Message handle(const cs::Message &msg)
{
    if (msg.command == "GET_PUBLIC")
    {
        KeyServer keyserver;
        return ok({{"g", element_to_blob(g)}, {"public_key", element_to_blob(keyserver.public_key)}});
    }

    if (msg.command == "HARDEN")
    {
        KeyServer keyserver;
        element_t a, b;
        element_init_G1(a, pairing);
        element_init_G1(b, pairing);
        blob_to_element(a, cs::require_field(msg, "a"));
        keyserver.hardenPassword(b, a);
        string b_blob = element_to_blob(b);
        string public_key = element_to_blob(keyserver.public_key);
        element_clear(a);
        element_clear(b);
        return ok({{"b", b_blob}, {"public_key", public_key}});
    }

    if (msg.command == "REGISTER")
    {
        CloudServer cloudserver;
        string id = cs::require_field(msg, "id");
        string cred = cs::require_field(msg, "cred_cs");
        cloudserver.store(id, cred);
        return ok({{"registered", "1"}});
    }

    if (msg.command == "ENCRYPT_KEY")
    {
        require_auth(msg);
        KeyServer keyserver;
        CloudServer cloudserver;
        string cred = cs::require_field(msg, "cred_cs");
        element_t c0, c1;
        element_init_G1(c0, pairing);
        element_init_G1(c1, pairing);
        keyserver.encrypt(c0, c1);
        cloudserver.encrypt(keyserver.getnr(), c0, c1, keyserver.public_key, cred);
        element_clear(c0);
        element_clear(c1);
        return ok({{"encrypted", "1"}});
    }

    if (msg.command == "RECOVER_KEY")
    {
        require_auth(msg);
        element_t mk;
        element_init_G1(mk, pairing);
        recover_original_mk(cs::require_field(msg, "cred_cs"), mk);
        string mk_blob = element_to_blob(mk);
        element_clear(mk);
        return ok({{"mk", mk_blob}});
    }

    if (msg.command == "UPLOAD")
    {
        require_auth(msg);
        int index = stoi(cs::require_field(msg, "index"));
        element_t mk;
        element_init_G1(mk, pairing);
        recover_original_mk(cs::require_field(msg, "cred_cs"), mk);
        original_file_encrypt_with_mk(mk, index, cs::require_field(msg, "plain"));
        element_clear(mk);
        return ok({{"count", "1"}, {"uploaded_files", "1"}});
    }

    if (msg.command == "SINGLE_QUERY")
    {
        require_auth(msg);
        int index = stoi(cs::require_field(msg, "index"));
        element_t mk;
        element_init_G1(mk, pairing);
        recover_original_mk(cs::require_field(msg, "cred_cs"), mk);
        string plain = original_file_decrypt_with_mk(mk, index, "Recover(ServerSingle)");
        element_clear(mk);
        return ok({{"name", file_prefix(index) + ".dat"}, {"plain", plain}});
    }

    if (msg.command == "UPDATE")
    {
        require_auth(msg);
        int index = stoi(cs::require_field(msg, "index"));
        if (!fs::exists(cipher_path_for(index)) || !fs::exists(iv_path_for(index)))
            return ok({{"updated", "0"}, {"existed", "0"}});

        element_t mk;
        element_init_G1(mk, pairing);
        recover_original_mk(cs::require_field(msg, "cred_cs"), mk);
        original_file_decrypt_with_mk(mk, index, "Recover(ServerUpdate)");
        original_file_encrypt_with_mk(mk, index, cs::require_field(msg, "plain"));
        element_clear(mk);
        return ok({{"updated", "1"}, {"existed", "1"}, {"updated_files", "1"}});
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
    cout << "PHE server listening on port " << port << " pid=" << getpid() << endl;

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
