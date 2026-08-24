#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <cryptopp/osrng.h>

#include "CSProtocol.h"
#include "Client.h"
#include "PublicParam.h"

using namespace std;
namespace fs = std::filesystem;

extern pairing_t pairing;

static constexpr int IPBCS_ITERATIONS = 1;
static constexpr int TEST_INDEX = 1;
static constexpr int DEFAULT_MAX_UPLOAD_FILES = 600;
static constexpr int DEFAULT_UPLOAD_STEP = 100;
static constexpr size_t TEST_FILE_BYTES = 1024 * 1024;

struct ModuleMetrics
{
    string name;
    int file_count = 0;
    int operation_files = 0;
    int uploaded_files = 0;
    int updated_files = 0;
    double client_ms = 0.0;
    double server_ms = 0.0;
    double rtt_ms = 0.0;
    size_t request_bytes = 0;
    size_t response_bytes = 0;
    string server_pid;

    void add_request(const cs::TimedResponse &response)
    {
        rtt_ms += response.rtt_ms;
        request_bytes += response.request_bytes;
        response_bytes += response.response_bytes;
        auto it = response.message.fields.find("server_time_ms");
        if (it != response.message.fields.end())
            server_ms += stod(it->second);
        auto pid_it = response.message.fields.find("server_pid");
        if (pid_it != response.message.fields.end() && server_pid.empty())
            server_pid = pid_it->second;
    }

    void add_iteration(const ModuleMetrics &other)
    {
        file_count += other.file_count;
        operation_files += other.operation_files;
        uploaded_files += other.uploaded_files;
        updated_files += other.updated_files;
        client_ms += other.client_ms;
        server_ms += other.server_ms;
        rtt_ms += other.rtt_ms;
        request_bytes += other.request_bytes;
        response_bytes += other.response_bytes;
        if (server_pid.empty())
            server_pid = other.server_pid;
    }

    void average(int n)
    {
        file_count /= n;
        operation_files /= n;
        uploaded_files /= n;
        updated_files /= n;
        client_ms /= n;
        server_ms /= n;
        rtt_ms /= n;
        request_bytes /= n;
        response_bytes /= n;
    }
};

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

static string file_name(int index)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%03d", index);
    return "Test_" + string(buf) + ".dat";
}

static void ensure_test_file(const fs::path &path, unsigned char salt)
{
    if (fs::exists(path) && fs::file_size(path) == TEST_FILE_BYTES)
        return;

    fs::create_directories(path.parent_path());
    string data(TEST_FILE_BYTES, '\0');
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<char>((i * 17 + salt) & 0xff);
    write_binary(path, data);
}

static void ensure_dataset(int max_files)
{
    for (int i = 1; i <= max_files; ++i)
    {
        ensure_test_file(fs::path("../File/TestMultiple/Origin") / file_name(i), static_cast<unsigned char>(0x41 + i));
        ensure_test_file(fs::path("../File/Update/Origin") / file_name(i), static_cast<unsigned char>(0xA1 + i));
    }
}

static vector<int> experiment_counts(int max_files, int step, int first)
{
    vector<int> counts;
    if (first > 0 && first <= max_files)
        counts.push_back(first);

    for (int count = step; count <= max_files; count += step)
    {
        if (counts.empty() || counts.back() != count)
            counts.push_back(count);
    }

    if (counts.empty() || counts.back() != max_files)
        counts.push_back(max_files);
    return counts;
}

static fs::path client_cipher_path_for(const string &kind, int index)
{
    return fs::path("../File/ClientWork") / kind / (file_name(index) + ".cipher");
}

static fs::path client_iv_path_for(const string &kind, int index)
{
    return fs::path("../File/ClientWork") / kind / (file_name(index) + ".iv");
}

static fs::path client_recover_path_for(const string &kind, int index)
{
    return fs::path("../File/ClientWork") / kind / (file_name(index) + ".recover");
}

static void sk_to_key(const string &sk, CryptoPP::byte *key)
{
    if (sk.size() < 16)
        throw runtime_error("sk is too short");
    memcpy(key, sk.data(), 16);
}

static pair<string, string> encrypt_file_locally(const string &sk, const fs::path &plain_path,
                                                 const string &kind, int index)
{
    fs::path cipher_path = client_cipher_path_for(kind, index);
    fs::path iv_path = client_iv_path_for(kind, index);
    fs::create_directories(cipher_path.parent_path());

    CryptoPP::byte key[16];
    sk_to_key(sk, key);
    CryptoPP::byte iv[16 * 16];
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, sizeof(iv));

    aes_EAX_FileEnc(plain_path.string(), key, iv, cipher_path.string());
    ofstream iv_out(iv_path, ios::binary);
    iv_out.write(reinterpret_cast<const char *>(iv), sizeof(iv));
    iv_out.close();

    string cipher = read_binary(cipher_path);
    string iv_blob = read_binary(iv_path);
    if (cipher.empty())
        throw runtime_error("local encryption produced empty cipher for " + kind + " index " + to_string(index));
    if (iv_blob.size() != sizeof(iv))
        throw runtime_error("local encryption produced invalid IV for " + kind + " index " + to_string(index));
    return {cipher, iv_blob};
}

static void decrypt_file_locally(const string &sk, const string &cipher, const string &iv_blob,
                                 const string &kind, int index)
{
    fs::path cipher_path = client_cipher_path_for(kind, index);
    fs::path iv_path = client_iv_path_for(kind, index);
    fs::path recover_path = client_recover_path_for(kind, index);
    write_binary(cipher_path, cipher);
    write_binary(iv_path, iv_blob);
    fs::create_directories(recover_path.parent_path());

    CryptoPP::byte key[16];
    sk_to_key(sk, key);
    CryptoPP::byte iv[16 * 16]{};
    if (iv_blob.size() != sizeof(iv))
        throw runtime_error("invalid IV size in " + kind + " index " + to_string(index) +
                            ": " + to_string(iv_blob.size()) + " bytes");
    memcpy(iv, iv_blob.data(), sizeof(iv));

    try
    {
        aes_EAX_FileDec(cipher_path.string(), key, iv, recover_path.string());
    }
    catch (const CryptoPP::Exception &ex)
    {
        throw runtime_error("local decryption failed in " + kind + " index " + to_string(index) + ": " + ex.what());
    }
}

static void phase_start(const string &name)
{
    cout << "\n[IPBCS Client] >>> " << name << " started" << endl;
}

static void phase_done(const string &name)
{
    cout << "[IPBCS Client] <<< " << name << " finished" << endl;
}

static void request_harden(const string &host, int port, Client &client, const string &id,
                           element_t &alpha, element_t &beta, element_t &public_key,
                           ModuleMetrics &metrics)
{
    client.blindPassword(alpha);
    cs::TimedResponse response = cs::request_timed(host, port, "HARDEN",
                                                   {{"id", id}, {"alpha", element_to_blob(alpha)}});
    metrics.add_request(response);
    blob_to_element(beta, cs::require_field(response.message, "beta"));
    blob_to_element(public_key, cs::require_field(response.message, "public_key"));
}

static ModuleMetrics registration_cs(const string &host, int port, string &psw, string &id)
{
    phase_start("Registration");
    ModuleMetrics metrics{"Registration"};
    auto start = chrono::high_resolution_clock::now();

    Client client(psw.data(), id.data());
    element_t alpha, beta, public_key;
    element_init_G1(alpha, pairing);
    element_init_G1(beta, pairing);
    element_init_G2(public_key, pairing);
    request_harden(host, port, client, id, alpha, beta, public_key, metrics);

    string s_u, cred_ks, cred_cs;
    client.CredentialGen(s_u, cred_ks, cred_cs, alpha, beta, public_key);
    metrics.add_request(cs::request_timed(host, port, "REGISTER",
                                          {{"id", id}, {"cred_cs", cred_cs}, {"cred_ks", cred_ks}, {"s_u", s_u}}));

    element_clear(alpha);
    element_clear(beta);
    element_clear(public_key);
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    phase_done("Registration");
    return metrics;
}

static ModuleMetrics key_gen_cs(const string &host, int port, string &psw, string &id)
{
    phase_start("KeyGen");
    ModuleMetrics metrics{"KeyGen"};
    auto start = chrono::high_resolution_clock::now();

    Client client(psw.data(), id.data());
    element_t alpha, beta, public_key;
    element_init_G1(alpha, pairing);
    element_init_G1(beta, pairing);
    element_init_G2(public_key, pairing);
    request_harden(host, port, client, id, alpha, beta, public_key, metrics);

    string psw_u_hat, EM_CS;
    CryptoPP::byte iv_CS[16];
    CryptoPP::AutoSeededRandomPool prng_cs;
    prng_cs.GenerateBlock(iv_CS, sizeof(iv_CS));
    client.loginToCS(psw_u_hat, EM_CS, iv_CS, alpha, beta, public_key);

    string iv_cs_blob(reinterpret_cast<char *>(iv_CS), sizeof(iv_CS));
    cs::TimedResponse cs_auth = cs::request_timed(host, port, "CS_GEN_AUTH",
                                                  {{"id", id}, {"EM_CS", EM_CS}, {"iv", iv_cs_blob}});
    metrics.add_request(cs_auth);
    string s_u = cs::require_field(cs_auth.message, "s_u");

    string EM_KS, ctx_sk, rho_u, gamma_u;
    CryptoPP::byte iv_KS[16];
    CryptoPP::AutoSeededRandomPool prng_ks;
    prng_ks.GenerateBlock(iv_KS, sizeof(iv_KS));
    client.loginToKS_KeyOutsource(EM_KS, ctx_sk, rho_u, gamma_u, iv_KS, s_u, psw_u_hat);

    string iv_ks_blob(reinterpret_cast<char *>(iv_KS), sizeof(iv_KS));
    metrics.add_request(cs::request_timed(host, port, "KS_GEN_AUTH",
                                          {{"id", id}, {"EM_KS", EM_KS}, {"iv", iv_ks_blob}, {"ctx_sk", ctx_sk}, {"rho_u", rho_u}}));
    metrics.add_request(cs::request_timed(host, port, "CS_RANDOM_STORE",
                                          {{"id", id}, {"gamma_u", gamma_u}}));

    element_clear(alpha);
    element_clear(beta);
    element_clear(public_key);
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    phase_done("KeyGen");
    return metrics;
}

static string retrieve_key_cs(const string &host, int port, string &psw, string &id, ModuleMetrics &metrics)
{
    Client client(psw.data(), id.data());
    element_t alpha, beta, public_key;
    element_init_G1(alpha, pairing);
    element_init_G1(beta, pairing);
    element_init_G2(public_key, pairing);
    request_harden(host, port, client, id, alpha, beta, public_key, metrics);

    string psw_u_hat, EM_CS;
    CryptoPP::byte iv_CS[16];
    CryptoPP::AutoSeededRandomPool prng_cs;
    prng_cs.GenerateBlock(iv_CS, sizeof(iv_CS));
    client.loginToCS(psw_u_hat, EM_CS, iv_CS, alpha, beta, public_key);

    string iv_cs_blob(reinterpret_cast<char *>(iv_CS), sizeof(iv_CS));
    cs::TimedResponse cs_auth = cs::request_timed(host, port, "CS_RETRIEVE_AUTH",
                                                  {{"id", id}, {"EM_CS", EM_CS}, {"iv", iv_cs_blob}});
    metrics.add_request(cs_auth);
    string s_u = cs::require_field(cs_auth.message, "s_u");
    string gamma_u = cs::require_field(cs_auth.message, "gamma_u");

    string EM_KS;
    CryptoPP::byte iv_KS[16];
    CryptoPP::AutoSeededRandomPool prng_ks;
    prng_ks.GenerateBlock(iv_KS, sizeof(iv_KS));
    client.loginToKS(psw_u_hat, s_u, EM_KS, iv_KS);

    string iv_ks_blob(reinterpret_cast<char *>(iv_KS), sizeof(iv_KS));
    cs::TimedResponse ks_auth = cs::request_timed(host, port, "KS_RETRIEVE_AUTH",
                                                  {{"id", id}, {"EM_KS", EM_KS}, {"iv", iv_ks_blob}});
    metrics.add_request(ks_auth);
    string ctx_sk = cs::require_field(ks_auth.message, "ctx_sk");
    string rho_u = cs::require_field(ks_auth.message, "rho_u");

    string sk;
    client.retrieval(sk, gamma_u, psw_u_hat, ctx_sk, rho_u);

    element_clear(alpha);
    element_clear(beta);
    element_clear(public_key);
    return sk;
}

static ModuleMetrics key_retrieve_cs(const string &host, int port, string &psw, string &id)
{
    phase_start("KeyRetrieve");
    ModuleMetrics metrics{"KeyRetrieve"};
    auto start = chrono::high_resolution_clock::now();
    retrieve_key_cs(host, port, psw, id, metrics);
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    phase_done("KeyRetrieve");
    return metrics;
}

static void upload_one_file(const string &host, int port, const string &id, const string &sk,
                            int index, ModuleMetrics &metrics)
{
    string name = file_name(index);
    auto encrypted = encrypt_file_locally(sk, fs::path("../File/TestMultiple/Origin") / name, "Upload", index);
    metrics.add_request(cs::request_timed(host, port, "UPLOAD",
                                          {{"id", id}, {"index", to_string(index)}, {"name", name}, {"cipher", encrypted.first}, {"iv", encrypted.second}}));
}

static ModuleMetrics upload_single_cs(const string &host, int port, string &psw, string &id)
{
    phase_start("Upload");
    ModuleMetrics metrics{"Upload"};
    metrics.file_count = 1;
    metrics.operation_files = 1;
    metrics.uploaded_files = 1;
    auto start = chrono::high_resolution_clock::now();
    string sk = retrieve_key_cs(host, port, psw, id, metrics);
    upload_one_file(host, port, id, sk, TEST_INDEX, metrics);
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    phase_done("Upload");
    return metrics;
}

static vector<ModuleMetrics> upload_series_cs(const string &host, int port, string &psw, string &id,
                                              int max_files, int upload_step)
{
    phase_start("Upload series");
    ModuleMetrics running{"Upload100"};
    auto start = chrono::high_resolution_clock::now();
    string sk = retrieve_key_cs(host, port, psw, id, running);
    vector<int> checkpoints = experiment_counts(max_files, upload_step, 1);
    size_t next_checkpoint = 0;
    vector<ModuleMetrics> snapshots;

    for (int index = 1; index <= max_files; ++index)
    {
        upload_one_file(host, port, id, sk, index, running);
        if (next_checkpoint < checkpoints.size() && index == checkpoints[next_checkpoint])
        {
            ModuleMetrics snapshot = running;
            snapshot.name = "Upload" + to_string(index);
            snapshot.file_count = index;
            snapshot.operation_files = index;
            snapshot.uploaded_files = index;
            auto now = chrono::high_resolution_clock::now();
            snapshot.client_ms = chrono::duration<double, milli>(now - start).count() - snapshot.rtt_ms;
            snapshots.push_back(snapshot);
            cout << "[IPBCS Client] Upload progress: " << index << "/" << max_files << " files" << endl;
            ++next_checkpoint;
        }
    }

    phase_done("Upload series");
    return snapshots;
}

static vector<ModuleMetrics> upload_series_resume_cs(
    const string &host, int port, string &psw, string &id,
    const vector<int> &checkpoints, int start_index, ModuleMetrics running,
    const function<void(int, const ModuleMetrics &)> &commit)
{
    phase_start("Upload series (resumable)");
    ModuleMetrics auth{"UploadAuth"};
    auto auth_start = chrono::high_resolution_clock::now();
    string sk = retrieve_key_cs(host, port, psw, id, auth);
    auto auth_end = chrono::high_resolution_clock::now();
    auth.client_ms = chrono::duration<double, milli>(auth_end - auth_start).count() - auth.rtt_ms;
    if (start_index == 1)
        running.add_iteration(auth);

    vector<ModuleMetrics> snapshots;
    int index = start_index;
    for (int checkpoint : checkpoints)
    {
        if (checkpoint < start_index)
            continue;
        ModuleMetrics segment{"UploadSegment"};
        auto segment_start = chrono::high_resolution_clock::now();
        for (; index <= checkpoint; ++index)
            upload_one_file(host, port, id, sk, index, segment);
        auto segment_end = chrono::high_resolution_clock::now();
        segment.client_ms = chrono::duration<double, milli>(segment_end - segment_start).count() - segment.rtt_ms;
        running.add_iteration(segment);

        ModuleMetrics snapshot = running;
        snapshot.name = "Upload" + to_string(checkpoint);
        snapshot.file_count = checkpoint;
        snapshot.operation_files = checkpoint;
        snapshot.uploaded_files = checkpoint;
        commit(checkpoint, snapshot);
        snapshots.push_back(snapshot);
        cout << "[IPBCS Client] Upload checkpoint committed: " << checkpoint
             << "/" << checkpoints.back() << " files" << endl;
    }
    phase_done("Upload series (resumable)");
    return snapshots;
}

static ModuleMetrics single_query_cs(const string &host, int port, string &psw, string &id,
                                     int total_files, int operation_files)
{
    phase_start("SingleQuery");
    ModuleMetrics metrics{"SingleQuery"};
    metrics.file_count = total_files;
    metrics.operation_files = operation_files;
    auto start = chrono::high_resolution_clock::now();
    string sk = retrieve_key_cs(host, port, psw, id, metrics);
    for (int index = 1; index <= operation_files; ++index)
    {
        cs::TimedResponse query = cs::request_timed(host, port, "SINGLE_QUERY",
                                                    {{"id", id}, {"index", to_string(index)}});
        metrics.add_request(query);
        decrypt_file_locally(sk, cs::require_field(query.message, "cipher"),
                             cs::require_field(query.message, "iv"), "Recover(Single)", index);
    }
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    phase_done("SingleQuery");
    return metrics;
}

static ModuleMetrics batch_query_cs(const string &host, int port, string &psw, string &id,
                                    int total_files, int operation_files)
{
    phase_start("BatchQuery");
    ModuleMetrics metrics{"BatchQuery"};
    metrics.file_count = total_files;
    metrics.operation_files = operation_files;
    auto start = chrono::high_resolution_clock::now();
    string sk = retrieve_key_cs(host, port, psw, id, metrics);
    for (int index = 1; index <= operation_files; ++index)
    {
        cs::TimedResponse query = cs::request_timed(host, port, "SINGLE_QUERY",
                                                    {{"id", id}, {"index", to_string(index)}});
        metrics.add_request(query);
        decrypt_file_locally(sk, cs::require_field(query.message, "cipher"),
                             cs::require_field(query.message, "iv"), "Recover(Batch)", index);
    }
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    phase_done("BatchQuery");
    return metrics;
}

static ModuleMetrics update_cs(const string &host, int port, string &psw, string &id,
                               int total_files, int operation_files)
{
    phase_start("Update");
    ModuleMetrics metrics{"Update"};
    metrics.file_count = total_files;
    metrics.operation_files = operation_files;
    metrics.updated_files = operation_files;
    auto start = chrono::high_resolution_clock::now();
    string sk = retrieve_key_cs(host, port, psw, id, metrics);

    for (int index = 1; index <= operation_files; ++index)
    {
        cs::TimedResponse old_file = cs::request_timed(host, port, "SINGLE_QUERY",
                                                       {{"id", id}, {"index", to_string(index)}});
        metrics.add_request(old_file);
        decrypt_file_locally(sk, cs::require_field(old_file.message, "cipher"),
                             cs::require_field(old_file.message, "iv"), "Recover(Update)", index);

        string name = file_name(index);
        auto encrypted = encrypt_file_locally(sk, fs::path("../File/Update/Origin") / name, "Update", index);
        metrics.add_request(cs::request_timed(host, port, "UPDATE",
                                              {{"id", id}, {"index", to_string(index)}, {"name", name}, {"cipher", encrypted.first}, {"iv", encrypted.second}}));
    }

    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    phase_done("Update");
    return metrics;
}

static void print_metrics(const ModuleMetrics &m)
{
    double network_ms = max(0.0, m.rtt_ms - m.server_ms);
    size_t communication = m.request_bytes + m.response_bytes;
    cout << "[Client Metrics] module=" << m.name
         << " files=" << m.file_count
         << " operation_files=" << m.operation_files
         << " uploaded_files=" << m.uploaded_files
         << " updated_files=" << m.updated_files
         << " client_time_ms=" << m.client_ms
         << " server_time_ms=" << m.server_ms
         << " network_latency_ms=" << network_ms
         << " request_bytes=" << m.request_bytes
         << " response_bytes=" << m.response_bytes
         << " communication_overhead_bytes=" << communication
         << " server_pid=" << (m.server_pid.empty() ? "unknown" : m.server_pid)
         << endl;
}

static string csv_escape(const string &value)
{
    if (value.find_first_of(",\"\r\n") == string::npos)
        return value;
    string out = "\"";
    for (char c : value)
    {
        if (c == '"')
            out += "\"\"";
        else
            out += c;
    }
    out += "\"";
    return out;
}

struct ReportRow
{
    string module;
    string file_number;
    ModuleMetrics metrics;
};

struct CheckpointSample
{
    string module;
    int iteration = -1;
    int count = 0;
    ModuleMetrics metrics;
};

static string checkpoint_key(const string &module, int iteration, int count)
{
    return module + "|" + to_string(iteration) + "|" + to_string(count);
}

class CheckpointStore
{
public:
    CheckpointStore(fs::path path, string config) : path_(std::move(path)), config_(std::move(config))
    {
        load();
    }

    bool has(const string &module, int iteration, int count) const
    {
        return samples_.count(checkpoint_key(module, iteration, count)) != 0;
    }

    ModuleMetrics get(const string &module, int iteration, int count) const
    {
        auto it = samples_.find(checkpoint_key(module, iteration, count));
        if (it == samples_.end())
            throw runtime_error("missing checkpoint sample: " + module);
        return it->second.metrics;
    }

    void put(const string &module, int iteration, int count, const ModuleMetrics &metrics)
    {
        samples_[checkpoint_key(module, iteration, count)] = {module, iteration, count, metrics};
        save_atomic();
    }

    const fs::path &path() const { return path_; }

private:
    fs::path path_;
    string config_;
    map<string, CheckpointSample> samples_;

    void load()
    {
        if (!fs::exists(path_))
            return;
        ifstream in(path_, ios::binary);
        string line;
        if (!getline(in, line) || line != "config\t" + config_)
            throw runtime_error("checkpoint configuration does not match this run: " + path_.string());
        while (getline(in, line))
        {
            vector<string> fields;
            istringstream row(line);
            string field;
            while (getline(row, field, '\t'))
                fields.push_back(field);
            if (fields.size() != 14)
                continue;
            try
            {
                CheckpointSample sample;
                sample.module = fields[0];
                sample.iteration = stoi(fields[1]);
                sample.count = stoi(fields[2]);
                ModuleMetrics &m = sample.metrics;
                m.name = fields[3];
                m.file_count = stoi(fields[4]);
                m.operation_files = stoi(fields[5]);
                m.uploaded_files = stoi(fields[6]);
                m.updated_files = stoi(fields[7]);
                m.client_ms = stod(fields[8]);
                m.server_ms = stod(fields[9]);
                m.rtt_ms = stod(fields[10]);
                m.request_bytes = stoull(fields[11]);
                m.response_bytes = stoull(fields[12]);
                m.server_pid = fields[13];
                samples_[checkpoint_key(sample.module, sample.iteration, sample.count)] = sample;
            }
            catch (const exception &)
            {
            }
        }
    }

    void save_atomic() const
    {
        fs::create_directories(path_.parent_path());
        fs::path temp = path_;
        temp += ".tmp";
        ofstream out(temp, ios::binary | ios::trunc);
        if (!out)
            throw runtime_error("cannot write checkpoint: " + temp.string());
        out << "config\t" << config_ << "\n";
        out << setprecision(17);
        for (const auto &entry : samples_)
        {
            const CheckpointSample &sample = entry.second;
            const ModuleMetrics &m = sample.metrics;
            out << sample.module << '\t' << sample.iteration << '\t' << sample.count << '\t'
                << m.name << '\t' << m.file_count << '\t' << m.operation_files << '\t'
                << m.uploaded_files << '\t' << m.updated_files << '\t'
                << m.client_ms << '\t' << m.server_ms << '\t' << m.rtt_ms << '\t'
                << m.request_bytes << '\t' << m.response_bytes << '\t'
                << (m.server_pid.empty() ? "unknown" : m.server_pid) << '\n';
        }
        out.flush();
        if (!out)
            throw runtime_error("failed to flush checkpoint: " + temp.string());
        out.close();
        fs::rename(temp, path_);
    }
};

static string file_number_for(const ModuleMetrics &m)
{
    if (m.file_count <= 0)
        return "0";
    if (m.operation_files == m.file_count)
        return to_string(m.file_count);
    return to_string(m.operation_files) + "/" + to_string(m.file_count);
}

static fs::path write_metrics_csv(const vector<ReportRow> &rows)
{
    fs::create_directories("../Result");
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    tm local_tm{};
    localtime_r(&now_time, &local_tm);

    ostringstream name;
    name << put_time(&local_tm, "%Y%m%d") << "_IPBCS.csv";
    fs::path out_path = fs::path("../Result") / name.str();
    ofstream out(out_path, ios::binary);
    out << "module,file_number,client_ms,server_ms,totoal_overhead,network_ms,request_bytes,response_bytes,"
        << "communication_overhead_bytes,server_pid\n";
    for (const auto &row : rows)
    {
        const ModuleMetrics &m = row.metrics;
        double network_ms = max(0.0, m.rtt_ms - m.server_ms);
        double total_overhead = m.client_ms + m.server_ms + network_ms;
        out << csv_escape(row.module) << ","
            << csv_escape(row.file_number) << ","
            << fixed << setprecision(6) << m.client_ms << ","
            << fixed << setprecision(6) << m.server_ms << ","
            << fixed << setprecision(6) << total_overhead << ","
            << fixed << setprecision(6) << network_ms << ","
            << m.request_bytes << ","
            << m.response_bytes << ","
            << (m.request_bytes + m.response_bytes) << ","
            << csv_escape(m.server_pid.empty() ? "unknown" : m.server_pid) << "\n";
    }
    return out_path;
}

int main(int argc, char **argv)
{
    string host = argc > 1 ? argv[1] : cs::DEFAULT_HOST;
    int port = argc > 2 ? stoi(argv[2]) : cs::DEFAULT_PORT;
    string psw = argc > 3 ? argv[3] : "f4520tommy";
    string id = argc > 4 ? argv[4] : "wolverine";
    int max_files = argc > 5 ? stoi(argv[5]) : DEFAULT_MAX_UPLOAD_FILES;
    int upload_step = argc > 6 ? stoi(argv[6]) : DEFAULT_UPLOAD_STEP;
    int iterations = argc > 7 ? stoi(argv[7]) : IPBCS_ITERATIONS;
    string run_mode = argc > 8 ? argv[8] : "--resume";

    if (max_files <= 0 || upload_step <= 0 || iterations <= 0)
        throw runtime_error("max_files, upload_step, and iterations must be positive");

    if (run_mode != "--resume" && run_mode != "--fresh")
        throw runtime_error("run mode must be --resume or --fresh");

    fs::create_directories("../Result");
    fs::path checkpoint_path = fs::path("../Result") /
                               ("IPBCS_resume_" + to_string(max_files) + "_" + to_string(upload_step) + "_" +
                                to_string(iterations) + ".tsv");
    if (run_mode == "--fresh")
    {
        fs::remove(checkpoint_path);
        fs::remove(checkpoint_path.string() + ".tmp");
    }
    string checkpoint_config = "IPBCS|" + host + "|" + to_string(port) + "|" + id + "|" +
                               to_string(max_files) + "|" + to_string(upload_step) + "|" + to_string(iterations);
    CheckpointStore checkpoint(checkpoint_path, checkpoint_config);

    sysInitial();
    ensure_dataset(max_files);
    cout << "[IPBCS Client] Connected target " << host << ":" << port << endl;
    cout << "[IPBCS Client] Running " << iterations << " averaged rounds; max_files="
         << max_files << " upload_step=" << upload_step << endl;

    vector<int> upload_counts = experiment_counts(max_files, upload_step, 1);
    vector<int> query_counts = experiment_counts(max_files, upload_step, 1);
    vector<int> batch_counts = experiment_counts(max_files, upload_step, min(5, max_files));
    vector<int> update_counts = experiment_counts(max_files, upload_step, 1);

    ModuleMetrics registration_total{"Registration"};
    ModuleMetrics login_total{"Login"};
    vector<ModuleMetrics> upload_totals(upload_counts.size());
    vector<ModuleMetrics> single_query_totals(query_counts.size());
    vector<ModuleMetrics> batch_query_totals(batch_counts.size());
    vector<ModuleMetrics> update_totals(update_counts.size());
    if (!checkpoint.has("Registration", -1, 0))
    {
        ModuleMetrics measured = registration_cs(host, port, psw, id);
        checkpoint.put("Registration", -1, 0, measured);
    }
    else
        cout << "[IPBCS Client] Resume: Registration already completed" << endl;
    registration_total = checkpoint.get("Registration", -1, 0);

    if (!checkpoint.has("Setup", -1, 0))
    {
        key_gen_cs(host, port, psw, id);
        checkpoint.put("Setup", -1, 0, ModuleMetrics{"Setup"});
    }
    else
        cout << "[IPBCS Client] Resume: KeyGen already completed" << endl;

    if (!checkpoint.has("Login", 0, 0))
    {
        ModuleMetrics measured = key_retrieve_cs(host, port, psw, id);
        checkpoint.put("Login", 0, 0, measured);
    }

    int first_missing_upload = 0;
    ModuleMetrics upload_running{"Upload100"};
    for (size_t j = 0; j < upload_counts.size(); ++j)
    {
        if (!checkpoint.has("Upload", -1, upload_counts[j]))
        {
            first_missing_upload = static_cast<int>(j);
            break;
        }
        upload_running = checkpoint.get("Upload", -1, upload_counts[j]);
        first_missing_upload = static_cast<int>(j) + 1;
    }
    if (first_missing_upload < static_cast<int>(upload_counts.size()))
    {
        int start_index = first_missing_upload == 0 ? 1 : upload_counts[first_missing_upload - 1] + 1;
        upload_series_resume_cs(host, port, psw, id, upload_counts, start_index, upload_running,
                                [&](int count, const ModuleMetrics &metrics)
                                {
                                    checkpoint.put("Upload", -1, count, metrics);
                                });
    }
    else
        cout << "[IPBCS Client] Resume: Upload series already completed" << endl;

    for (int i = 0; i < iterations; ++i)
    {
        cout << "\n[IPBCS Client] ===== Iteration " << (i + 1) << "/" << iterations << " =====" << endl;
        if (!checkpoint.has("Login", i, 0))
        {
            ModuleMetrics measured = key_retrieve_cs(host, port, psw, id);
            checkpoint.put("Login", i, 0, measured);
        }
        else
            cout << "[IPBCS Client] Resume: KeyRetrieve iteration " << (i + 1) << " completed" << endl;

        for (size_t j = 0; j < query_counts.size(); ++j)
        {
            if (!checkpoint.has("SingleQuery", i, query_counts[j]))
            {
                ModuleMetrics measured = single_query_cs(host, port, psw, id, max_files, query_counts[j]);
                checkpoint.put("SingleQuery", i, query_counts[j], measured);
            }
            else
                cout << "[IPBCS Client] Resume: SingleQuery " << query_counts[j]
                     << " iteration " << (i + 1) << " completed" << endl;
        }
        for (size_t j = 0; j < batch_counts.size(); ++j)
        {
            if (!checkpoint.has("BatchQuery", i, batch_counts[j]))
            {
                ModuleMetrics measured = batch_query_cs(host, port, psw, id, max_files, batch_counts[j]);
                checkpoint.put("BatchQuery", i, batch_counts[j], measured);
            }
            else
                cout << "[IPBCS Client] Resume: BatchQuery " << batch_counts[j]
                     << " iteration " << (i + 1) << " completed" << endl;
        }
        for (size_t j = 0; j < update_counts.size(); ++j)
        {
            if (!checkpoint.has("Update", i, update_counts[j]))
            {
                ModuleMetrics measured = update_cs(host, port, psw, id, max_files, update_counts[j]);
                checkpoint.put("Update", i, update_counts[j], measured);
            }
            else
                cout << "[IPBCS Client] Resume: Update " << update_counts[j]
                     << " iteration " << (i + 1) << " completed" << endl;
        }
    }

    for (int i = 0; i < iterations; ++i)
    {
        login_total.add_iteration(checkpoint.get("Login", i, 0));
        for (size_t j = 0; j < query_counts.size(); ++j)
            single_query_totals[j].add_iteration(checkpoint.get("SingleQuery", i, query_counts[j]));
        for (size_t j = 0; j < batch_counts.size(); ++j)
            batch_query_totals[j].add_iteration(checkpoint.get("BatchQuery", i, batch_counts[j]));
        for (size_t j = 0; j < update_counts.size(); ++j)
            update_totals[j].add_iteration(checkpoint.get("Update", i, update_counts[j]));
    }
    for (size_t j = 0; j < upload_counts.size(); ++j)
        upload_totals[j] = checkpoint.get("Upload", -1, upload_counts[j]);

    login_total.average(iterations);
    for (auto &m : single_query_totals)
        m.average(iterations);
    for (auto &m : batch_query_totals)
        m.average(iterations);
    for (auto &m : update_totals)
        m.average(iterations);

    vector<ReportRow> rows;
    rows.push_back({"Registration", "0", registration_total});
    rows.push_back({"Login", "0", login_total});
    for (size_t i = 0; i < upload_totals.size(); ++i)
        rows.push_back({i == 0 ? "Upload" : "", file_number_for(upload_totals[i]), upload_totals[i]});
    for (size_t i = 0; i < single_query_totals.size(); ++i)
        rows.push_back({i == 0 ? "SingleQuery" : "", file_number_for(single_query_totals[i]), single_query_totals[i]});
    for (size_t i = 0; i < batch_query_totals.size(); ++i)
        rows.push_back({i == 0 ? "BatchQuery" : "", file_number_for(batch_query_totals[i]), batch_query_totals[i]});
    for (size_t i = 0; i < update_totals.size(); ++i)
        rows.push_back({i == 0 ? "Update" : "", file_number_for(update_totals[i]), update_totals[i]});

    print_metrics(registration_total);
    print_metrics(login_total);
    for (const auto &m : upload_totals)
        print_metrics(m);
    for (const auto &m : single_query_totals)
        print_metrics(m);
    for (const auto &m : batch_query_totals)
        print_metrics(m);
    for (const auto &m : update_totals)
        print_metrics(m);

    fs::path csv_path = write_metrics_csv(rows);
    cout << "CS metrics CSV saved to " << csv_path << endl;
    cout << "Resume checkpoint saved to " << checkpoint.path() << endl;
    return 0;
}
