#include <algorithm>
#include <chrono>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "CSProtocol.h"
#include "PublicParam.h"

using namespace std;
namespace fs = std::filesystem;

struct LoginSession
{
    string y;
    string Y;
    string sigma_s;
};

static unordered_map<string, LoginSession> sessions;
static unique_ptr<HVC> hvc_instance;
static int hvc_size = 0;

static string element_to_string(element_t e)
{
    char buffer[4096];
    int len = element_snprint(buffer, sizeof(buffer), e);
    return string(buffer, len);
}

static void set_g1_from_string(element_t e, const string &value)
{
    if (element_set_str(e, value.c_str(), 10) == 0)
        throw runtime_error("failed to parse G1 element");
}

static void set_zr_from_string(element_t e, const string &value)
{
    if (element_set_str(e, value.c_str(), 10) == 0)
        throw runtime_error("failed to parse Zr element");
}

static void ensure_hvc(int n)
{
    if (!hvc_instance || hvc_size != n)
    {
        hvc_instance = make_unique<HVC>(n, pairing);
        hvc_size = n;
    }
}

static vector<fs::path> sorted_files(const fs::path &dir)
{
    vector<fs::path> files;
    if (!fs::exists(dir))
        return files;
    for (const auto &entry : fs::directory_iterator(dir))
        if (entry.is_regular_file())
            files.push_back(entry.path());
    sort(files.begin(), files.end(), [](const fs::path &a, const fs::path &b)
         { return a.filename().string() < b.filename().string(); });
    return files;
}

static string read_binary_string(const fs::path &path)
{
    string data;
    if (!read_file_binary(path.string(), data))
        throw runtime_error("failed to read file: " + path.string());
    return data;
}

static void write_binary_string(const fs::path &path, const string &data)
{
    fs::create_directories(path.parent_path());
    vector<unsigned char> bytes(data.begin(), data.end());
    if (!write_file_all(path, bytes))
        throw runtime_error("failed to write file: " + path.string());
}

static cs::Message ok(map<string, string> fields)
{
    return {"OK", std::move(fields)};
}

static cs::Message handle_oprf(const cs::Message &msg)
{
    element_t alpha, beta, k_o;
    element_init_G1(alpha, pairing);
    element_init_G1(beta, pairing);
    element_init_Zr(k_o, pairing);

    set_g1_from_string(alpha, cs::require_field(msg, "alpha"));
    if (!Load_element_Zr("../Storage/k_o.txt", k_o))
        throw runtime_error("failed to load k_o");

    element_pow_zn(beta, alpha, k_o);
    string beta_str = element_to_string(beta);

    element_clear(alpha);
    element_clear(beta);
    element_clear(k_o);
    return ok({{"beta", beta_str}});
}

static cs::Message handle_registration_finish(const cs::Message &msg)
{
    fs::create_directories("../Storage");

    const string rho = cs::require_field(msg, "rho");
    const string pk_u = cs::require_field(msg, "pk_u");

    element_t rho_elem, pk_u_elem, sk_s;
    element_init_G1(rho_elem, pairing);
    element_init_G1(pk_u_elem, pairing);
    element_init_Zr(sk_s, pairing);
    set_g1_from_string(rho_elem, rho);
    set_g1_from_string(pk_u_elem, pk_u);

    save_element_G1("../Storage/rho.txt", rho_elem);
    save_element_G1("../Storage/user_public_key.txt", pk_u_elem);

    if (!Load_element_Zr("../Storage/server_secre_key.txt", sk_s))
        throw runtime_error("failed to load server secret key");

    string sigma_rho = Sign(rho + pk_u, sk_s);
    save_string_to_file(sigma_rho, "../Storage/sigma_rho");

    element_clear(rho_elem);
    element_clear(pk_u_elem);
    element_clear(sk_s);
    return ok({{"sigma_rho", sigma_rho}});
}

static cs::Message handle_login_challenge()
{
    element_t y, Y, sk_s;
    element_init_Zr(y, pairing);
    element_random(y);
    element_init_G1(Y, pairing);
    element_pow_zn(Y, g, y);
    element_init_Zr(sk_s, pairing);

    if (!Load_element_Zr("../Storage/server_secre_key.txt", sk_s))
        throw runtime_error("failed to load server secret key");

    string Y_str = element_to_string(Y);
    string y_str = element_to_string(y);
    string sigma_s = Sign(Y_str, sk_s);
    string sid = to_string(time(nullptr)) + "_" + to_string(rand());
    sessions[sid] = {y_str, Y_str, sigma_s};

    element_clear(y);
    element_clear(Y);
    element_clear(sk_s);
    return ok({{"sid", sid}, {"Y", Y_str}, {"sigma_s", sigma_s}});
}

static cs::Message handle_login_finish(const cs::Message &msg)
{
    const string sid = cs::require_field(msg, "sid");
    auto it = sessions.find(sid);
    if (it == sessions.end())
        throw runtime_error("unknown login session");

    const LoginSession session = it->second;
    sessions.erase(it);

    const string rho = cs::require_field(msg, "rho");
    const string X_str = cs::require_field(msg, "X");
    const string sigma_u = cs::require_field(msg, "sigma_u");

    element_t pk_s, pk_u, X, y, server_gxy, server_k_se;
    element_init_G1(pk_s, pairing);
    element_init_G1(pk_u, pairing);
    element_init_G1(X, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(server_gxy, pairing);
    element_init_G1(server_k_se, pairing);

    if (!Load_element_G1("../Storage/server_public_key.txt", pk_s))
        throw runtime_error("failed to load server public key");
    if (!Load_element_G1("../Storage/user_public_key.txt", pk_u))
        throw runtime_error("failed to load user public key");

    string pk_u_str = element_to_string(pk_u);
    string sigma_rho;
    if (!load_string_from_file("../Storage/sigma_rho", sigma_rho))
        throw runtime_error("failed to load sigma_rho");

    string user_signed = X_str + session.Y + session.sigma_s;
    bool ok_rho = Verify(rho + pk_u_str, sigma_rho, pk_s);
    bool ok_user = Verify(user_signed, sigma_u, pk_u);
    if (!ok_rho || !ok_user)
        throw runtime_error("login verification failed");

    set_g1_from_string(X, X_str);
    set_zr_from_string(y, session.y);
    element_pow_zn(server_gxy, X, y);

    string server_gxy_str = element_to_string(server_gxy);
    string server_seed = session.sigma_s + sigma_u + X_str + session.Y + server_gxy_str;
    element_from_hash(server_k_se, (void *)server_seed.c_str(), server_seed.length());

    string k_se = element_to_string(server_k_se);
    element_clear(pk_s);
    element_clear(pk_u);
    element_clear(X);
    element_clear(y);
    element_clear(server_gxy);
    element_clear(server_k_se);
    return ok({{"verified", "1"}, {"k_se", k_se}});
}

static cs::Message handle_upload(const cs::Message &msg)
{
    int n = stoi(cs::require_field(msg, "n"));
    int start = 0;
    auto start_it = msg.fields.find("start");
    if (start_it != msg.fields.end())
        start = stoi(start_it->second);
    if (start < 0 || start > n)
        throw runtime_error("invalid upload start");

    ensure_hvc(n);
    fs::create_directories("../File/Cipher");
    fs::create_directories("../File/Tag");
    fs::create_directories("../File/Proof");

    vector<string> tags;
    tags.reserve(n);
    auto cipher_files = sorted_files("../File/Cipher");
    if (start > static_cast<int>(cipher_files.size()))
        throw runtime_error("incremental upload start exceeds existing file count");

    for (int i = 0; i < start; ++i)
    {
        string name = cipher_files[i].filename().string();
        tags.push_back(read_binary_string(fs::path("../File/Tag") / (name + ".tag")));
    }

    for (int i = start; i < n; ++i)
    {
        string idx = to_string(i);
        string name = cs::require_field(msg, "name_" + idx);
        string cipher = cs::require_field(msg, "cipher_" + idx);
        string tag = cs::require_field(msg, "tag_" + idx);
        write_binary_string(fs::path("../File/Cipher") / name, cipher);
        write_binary_string(fs::path("../File/Tag") / (name + ".tag"), tag);
        tags.push_back(tag);
    }
    if (static_cast<int>(tags.size()) != n)
        throw runtime_error("upload tag count mismatch");

    HVC &hvc = *hvc_instance;
    pairing_t &pairing_hvc = hvc.GetPairing();
    vector<element_t> m(n);
    for (int i = 0; i < n; ++i)
    {
        element_init_Zr(m[i], pairing_hvc);
        element_from_hash(m[i], (void *)tags[i].data(), tags[i].size());
    }

    element_t r;
    element_init_Zr(r, pairing_hvc);
    set_zr_from_string(r, cs::require_field(msg, "r"));

    for (int i = 0; i < n; ++i)
    {
        element_t Lambda_i;
        element_init_G1(Lambda_i, pairing_hvc);
        hvc.open(m.data(), n, i, r, Lambda_i);
        save_element_G1_compressed("../File/Proof/Lambda_i_" + to_string(i) + ".dat", Lambda_i);
        element_clear(Lambda_i);
    }

    for (int i = 0; i < n; ++i)
        element_clear(m[i]);
    element_clear(r);
    return ok({{"files", to_string(n)}, {"uploaded_files", to_string(n - start)}});
}

static cs::Message handle_single_query(const cs::Message &msg)
{
    int n = stoi(cs::require_field(msg, "n"));
    int index = stoi(cs::require_field(msg, "index"));
    ensure_hvc(n);

    auto cipher_files = sorted_files("../File/Cipher");
    if (index < 0 || index >= static_cast<int>(cipher_files.size()))
        throw runtime_error("query index out of range");

    fs::path cipher_path = cipher_files[index];
    string name = cipher_path.filename().string();
    string cipher = read_binary_string(cipher_path);
    string tag = read_binary_string(fs::path("../File/Tag") / (name + ".tag"));
    string proof = read_binary_string("../File/Proof/Lambda_i_" + to_string(index) + ".dat");
    return ok({{"name", name}, {"cipher", cipher}, {"tag", tag}, {"proof", proof}, {"index", to_string(index)}});
}

static cs::Message handle_batch_query(const cs::Message &msg)
{
    int n = stoi(cs::require_field(msg, "n"));
    int count = stoi(cs::require_field(msg, "count"));
    ensure_hvc(n);
    string proof_mode = "aggregate";
    auto proof_mode_it = msg.fields.find("proof_mode");
    if (proof_mode_it != msg.fields.end())
        proof_mode = proof_mode_it->second;
    bool individual_proofs = proof_mode == "individual";

    auto cipher_files = sorted_files("../File/Cipher");
    map<string, string> fields;
    fields["count"] = to_string(count);
    HVC &hvc = *hvc_instance;
    pairing_t &pairing_hvc = hvc.GetPairing();
    element_t proof_agg;
    element_init_G1(proof_agg, pairing_hvc);
    element_set1(proof_agg);

    for (int i = 0; i < count; ++i)
    {
        int index = stoi(cs::require_field(msg, "index_" + to_string(i)));
        if (index < 0 || index >= static_cast<int>(cipher_files.size()))
            throw runtime_error("batch query index out of range");

        fs::path cipher_path = cipher_files[index];
        string name = cipher_path.filename().string();
        string key = to_string(i);
        fields["index_" + key] = to_string(index);
        fields["name_" + key] = name;
        fields["cipher_" + key] = read_binary_string(cipher_path);
        fields["tag_" + key] = read_binary_string(fs::path("../File/Tag") / (name + ".tag"));
        string proof = read_binary_string("../File/Proof/Lambda_i_" + to_string(index) + ".dat");
        if (individual_proofs)
        {
            fields["proof_" + key] = proof;
        }
        else
        {
            element_t Lambda_i;
            element_init_G1(Lambda_i, pairing_hvc);
            vector<unsigned char> proof_buf(proof.begin(), proof.end());
            element_from_bytes_compressed(Lambda_i, proof_buf.data());
            element_mul(proof_agg, proof_agg, Lambda_i);
            element_clear(Lambda_i);
        }
    }
    if (!individual_proofs)
    {
        int len = element_length_in_bytes_compressed(proof_agg);
        vector<unsigned char> buf(len);
        element_to_bytes_compressed(buf.data(), proof_agg);
        fields["proof_agg"] = string(reinterpret_cast<const char *>(buf.data()), buf.size());
    }
    element_clear(proof_agg);
    return ok(fields);
}

static cs::Message handle_update(const cs::Message &msg)
{
    int n = stoi(cs::require_field(msg, "n"));
    int count = stoi(cs::require_field(msg, "count"));
    if (count < 0 || count > n)
        throw runtime_error("invalid update count");
    ensure_hvc(n);

    auto cipher_files = sorted_files("../File/Cipher");
    if (n > static_cast<int>(cipher_files.size()))
        throw runtime_error("update file count exceeds uploaded files");

    HVC &hvc = *hvc_instance;
    pairing_t &pairing_hvc = hvc.GetPairing();
    vector<element_t> delta_vec(n);
    for (int i = 0; i < n; ++i)
    {
        element_init_Zr(delta_vec[i], pairing_hvc);
        element_set0(delta_vec[i]);
    }

    for (int i = 0; i < count; ++i)
    {
        string k = to_string(i);
        int index = stoi(cs::require_field(msg, "index_" + k));
        if (index < 0 || index >= n)
            throw runtime_error("update index out of range");

        string name = cs::require_field(msg, "name_" + k);
        string cipher = cs::require_field(msg, "cipher_" + k);
        string tag = cs::require_field(msg, "tag_" + k);
        string delta = cs::require_field(msg, "delta_" + k);

        element_t delta_tag;
        element_init_Zr(delta_tag, pairing_hvc);
        set_zr_from_string(delta_tag, delta);
        element_set(delta_vec[index], delta_tag);
        element_clear(delta_tag);

        write_binary_string(fs::path("../File/Cipher") / name, cipher);
        write_binary_string(fs::path("../File/Tag") / (name + ".tag"), tag);
    }

    element_t r_delta;
    element_init_Zr(r_delta, pairing_hvc);
    set_zr_from_string(r_delta, cs::require_field(msg, "r_delta"));

    for (int i = 0; i < n; ++i)
    {
        element_t Lambda_old, Lambda_delta, Lambda_new;
        element_init_G1(Lambda_old, pairing_hvc);
        element_init_G1(Lambda_delta, pairing_hvc);
        element_init_G1(Lambda_new, pairing_hvc);
        load_element_G1_compressed("../File/Proof/Lambda_i_" + to_string(i) + ".dat", Lambda_old);
        hvc.open(delta_vec.data(), n, i, r_delta, Lambda_delta);
        hvc.openHom(Lambda_old, Lambda_delta, Lambda_new);
        save_element_G1_compressed("../File/Proof/Lambda_i_" + to_string(i) + ".dat", Lambda_new);
        element_clear(Lambda_old);
        element_clear(Lambda_delta);
        element_clear(Lambda_new);
    }

    for (int i = 0; i < n; ++i)
        element_clear(delta_vec[i]);
    element_clear(r_delta);
    return ok({{"updated", "1"}, {"updated_files", to_string(count)}});
}

static cs::Message dispatch(const cs::Message &msg)
{
    if (msg.command == "REG_OPRF" || msg.command == "LOGIN_OPRF")
        return handle_oprf(msg);
    if (msg.command == "REG_FINISH")
        return handle_registration_finish(msg);
    if (msg.command == "LOGIN_CHALLENGE")
        return handle_login_challenge();
    if (msg.command == "LOGIN_FINISH")
        return handle_login_finish(msg);
    if (msg.command == "UPLOAD")
        return handle_upload(msg);
    if (msg.command == "SINGLE_QUERY")
        return handle_single_query(msg);
    if (msg.command == "BATCH_QUERY")
        return handle_batch_query(msg);
    if (msg.command == "UPDATE")
        return handle_update(msg);
    throw runtime_error("unknown command: " + msg.command);
}

static void refresh_server_public_key()
{
    element_t sk_s, pk_s;
    element_init_Zr(sk_s, pairing);
    element_init_G1(pk_s, pairing);

    if (!Load_element_Zr("../Storage/server_secre_key.txt", sk_s))
        throw runtime_error("failed to load server secret key");

    element_pow_zn(pk_s, g, sk_s);
    save_element_G1("../Storage/server_public_key.txt", pk_s);

    element_clear(sk_s);
    element_clear(pk_s);
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? stoi(argv[1]) : cs::DEFAULT_PORT;
    srand(static_cast<unsigned int>(time(nullptr)));
    signal(SIGPIPE, SIG_IGN);

    sysInitial();
    refresh_server_public_key();
    int listener = cs::listen_socket(port);
    cout << "HRACS server listening on 0.0.0.0:" << port << " pid=" << getpid() << endl;

    while (true)
    {
        sockaddr_in peer_addr{};
        socklen_t peer_len = sizeof(peer_addr);
        int client = accept(listener, reinterpret_cast<sockaddr *>(&peer_addr), &peer_len);
        if (client < 0)
            continue;

        char peer_ip[INET_ADDRSTRLEN] = "unknown";
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
        string peer = string(peer_ip) + ":" + to_string(ntohs(peer_addr.sin_port));
        string command = "UNKNOWN";
        size_t request_bytes = 0;
        size_t response_bytes = 0;
        double server_ms = 0.0;
        try
        {
            string payload;
            if (!cs::recv_frame(client, payload))
                throw runtime_error("failed to receive request");
            request_bytes = payload.size() + sizeof(uint32_t);
            cs::Message request = cs::parse_message(payload);
            command = request.command;

            auto start = chrono::high_resolution_clock::now();
            cs::Message response = dispatch(request);
            auto end = chrono::high_resolution_clock::now();
            server_ms = chrono::duration<double, milli>(end - start).count();
            response.fields["server_time_ms"] = to_string(server_ms);
            response.fields["server_pid"] = to_string(getpid());

            string response_payload = cs::build_message(response.command, response.fields);
            response_bytes = response_payload.size() + sizeof(uint32_t);
            cs::send_frame(client, response_payload);
        }
        catch (const exception &ex)
        {
            string response_payload = cs::build_message("ERR", {{"message", ex.what()}, {"server_time_ms", to_string(server_ms)}, {"server_pid", to_string(getpid())}});
            response_bytes = response_payload.size() + sizeof(uint32_t);
            cs::send_frame(client, response_payload);
            cerr << "Request failed: " << ex.what() << endl;
        }

        cout << "[Server Metrics] module=" << command
             << " peer=" << peer
             << " pid=" << getpid()
             << " server_time_ms=" << server_ms
             << " request_bytes=" << request_bytes
             << " response_bytes=" << response_bytes
             << " communication_overhead_bytes=" << (request_bytes + response_bytes)
             << endl;
        close(client);
    }
}
