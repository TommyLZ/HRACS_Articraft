#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "CSProtocol.h"
#include "PublicParam.h"

using namespace std;
namespace fs = std::filesystem;

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
        if (pid_it != response.message.fields.end())
            server_pid = server_pid.empty() ? pid_it->second : server_pid;
    }
};

static vector<ModuleMetrics> all_metrics;

static string test_file_name(int index)
{
    int number = index + 1;
    return "Test_" + string(number < 10 ? "00" : number < 100 ? "0"
                                                              : "") +
           to_string(number) + ".dat";
}

static void ensure_test_file(const fs::path &path, int index, unsigned char salt)
{
    if (fs::exists(path) && fs::file_size(path) == TEST_FILE_BYTES)
        return;

    fs::create_directories(path.parent_path());
    vector<unsigned char> data(TEST_FILE_BYTES);
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<unsigned char>((index * 131 + i * 17 + salt) & 0xff);
    if (!write_file_all(path, data))
        throw runtime_error("failed to create test file: " + path.string());
}

static void ensure_test_dataset(int n)
{
    for (int i = 0; i < n; ++i)
    {
        string name = test_file_name(i);
        ensure_test_file(fs::path("../File/Origin") / name, i, 0x21);
        ensure_test_file(fs::path("../File/Update/Origin") / name, i, 0x83);
    }
}

static vector<int> parse_sizes(const string &value)
{
    vector<int> sizes;
    size_t start = 0;
    while (start <= value.size())
    {
        size_t comma = value.find(',', start);
        string token = value.substr(start, comma == string::npos ? string::npos : comma - start);
        if (!token.empty())
        {
            int n = stoi(token);
            if (n <= 0)
                throw runtime_error("file counts must be positive");
            sizes.push_back(n);
        }
        if (comma == string::npos)
            break;
        start = comma + 1;
    }
    if (sizes.empty())
        throw runtime_error("empty file count list");
    return sizes;
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

static vector<unsigned char> derive_dek_key()
{
    string seed;
    if (!load_string_from_file("../Storage/seed.txt", seed))
        throw runtime_error("failed to load seed.txt");

    string seed_dek = seed + "DEK";
    element_t k_dek;
    element_init_Zr(k_dek, pairing);
    element_from_hash(k_dek, (void *)seed_dek.c_str(), seed_dek.length());

    int len = element_length_in_bytes(k_dek);
    vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), k_dek);

    vector<unsigned char> key(32);
    SHA256(buf.data(), buf.size(), key.data());
    element_clear(k_dek);
    return key;
}

static pair<string, string> encrypt_file_payload(const fs::path &in_path, const vector<unsigned char> &key)
{
    vector<unsigned char> plaintext;
    if (!read_file_all(in_path, plaintext))
        throw runtime_error("failed to read plaintext file: " + in_path.string());

    string filename = in_path.filename().string();
    vector<unsigned char> aad(filename.begin(), filename.end());
    vector<unsigned char> iv, ciphertext, tag;
    if (!aes_gcm_encrypt(plaintext, aad, key, iv, ciphertext, tag))
        throw runtime_error("AES-GCM encryption failed: " + in_path.string());

    string cipher;
    cipher.reserve(iv.size() + ciphertext.size());
    cipher.append(reinterpret_cast<const char *>(iv.data()), iv.size());
    cipher.append(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
    string tag_str(reinterpret_cast<const char *>(tag.data()), tag.size());
    return {cipher, tag_str};
}

static void decrypt_payload_to_file(const string &name, const string &cipher, const string &tag,
                                    const fs::path &out_dir, const vector<unsigned char> &key)
{
    if (cipher.size() < IV_LEN)
        throw runtime_error("ciphertext too short");

    vector<unsigned char> iv(cipher.begin(), cipher.begin() + IV_LEN);
    vector<unsigned char> ciphertext(cipher.begin() + IV_LEN, cipher.end());
    vector<unsigned char> tag_vec(tag.begin(), tag.end());
    vector<unsigned char> aad(name.begin(), name.end());
    vector<unsigned char> plaintext;
    if (!aes_gcm_decrypt(ciphertext, aad, key, iv, tag_vec, plaintext))
        throw runtime_error("decrypt/auth failed: " + name);

    fs::create_directories(out_dir);
    if (!write_file_all(out_dir / name, plaintext))
        throw runtime_error("failed to write decrypted file");
}

static bool verify_proof_from_payload(HVC &hvc, const string &C_bin, const string &proof_bin,
                                      const string &tag, int index)
{
    pairing_t &pairing_hvc = hvc.GetPairing();
    element_t C, Lambda, m;
    element_init_G1(C, pairing_hvc);
    element_init_G1(Lambda, pairing_hvc);
    element_init_Zr(m, pairing_hvc);
    vector<unsigned char> C_buf(C_bin.begin(), C_bin.end());
    vector<unsigned char> proof_buf(proof_bin.begin(), proof_bin.end());
    element_from_bytes_compressed(C, C_buf.data());
    element_from_bytes_compressed(Lambda, proof_buf.data());
    element_from_hash(m, (void *)tag.data(), tag.size());
    bool ok = hvc.verify(C, m, Lambda, index);
    element_clear(C);
    element_clear(Lambda);
    element_clear(m);
    return ok;
}

static bool verify_aggregate_proof_from_payload(HVC &hvc, const string &C_bin, const string &proof_bin,
                                                const vector<string> &tags, const vector<int> &indices)
{
    if (tags.size() != indices.size())
        throw runtime_error("aggregate proof input size mismatch");

    pairing_t &pairing_hvc = hvc.GetPairing();
    element_t C, Lambda_agg;
    element_init_G1(C, pairing_hvc);
    element_init_G1(Lambda_agg, pairing_hvc);
    vector<unsigned char> C_buf(C_bin.begin(), C_bin.end());
    vector<unsigned char> proof_buf(proof_bin.begin(), proof_bin.end());
    element_from_bytes_compressed(C, C_buf.data());
    element_from_bytes_compressed(Lambda_agg, proof_buf.data());

    vector<element_t> messages(tags.size());
    for (size_t i = 0; i < tags.size(); ++i)
    {
        element_init_Zr(messages[i], pairing_hvc);
        element_from_hash(messages[i], (void *)tags[i].data(), tags[i].size());
    }

    bool ok = hvc.verifyAggregate(C, indices, messages, Lambda_agg);

    for (size_t i = 0; i < messages.size(); ++i)
        element_clear(messages[i]);
    element_clear(C);
    element_clear(Lambda_agg);
    return ok;
}

static string g1_to_compressed_string(element_t e)
{
    int len = element_length_in_bytes_compressed(e);
    vector<unsigned char> buf(len);
    element_to_bytes_compressed(buf.data(), e);
    return string(reinterpret_cast<const char *>(buf.data()), buf.size());
}

static void set_g1_from_compressed_string(element_t e, const string &value)
{
    vector<unsigned char> buf(value.begin(), value.end());
    element_from_bytes_compressed(e, buf.data());
}

static string read_local_commitment()
{
    return read_binary_string("../File/Commit/C.dat");
}

static void save_local_commitment(element_t &C)
{
    write_binary_string("../File/Commit/C.dat", g1_to_compressed_string(C));
}

static void save_local_randomness(element_t &r)
{
    fs::create_directories("../File/Commit");
    if (!save_element_Zr("../File/Commit/r.dat", r))
        throw runtime_error("failed to save local commitment randomness");
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
    bool needs_quotes = value.find_first_of(",\"\r\n") != string::npos;
    if (!needs_quotes)
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
    name << put_time(&local_tm, "%Y%m%d") << "_HRACS.csv";
    fs::path out_path = fs::path("../Result") / name.str();

    ofstream out(out_path, ios::binary);
    if (!out)
        throw runtime_error("failed to open metrics csv for writing: " + out_path.string());

    out << "module,file_number,client_ms,server_ms,totoal_overhead,network_ms,request_bytes,response_bytes,"
        << "communication_overhead_bytes,server_pid\n";

    for (const auto &row : rows)
    {
        const ModuleMetrics &m = row.metrics;
        double network_ms = max(0.0, m.rtt_ms - m.server_ms);
        double total_overhead = m.client_ms + m.server_ms + network_ms;
        size_t communication = m.request_bytes + m.response_bytes;
        out << csv_escape(row.module) << ","
            << csv_escape(row.file_number) << ","
            << fixed << setprecision(6) << m.client_ms << ","
            << fixed << setprecision(6) << m.server_ms << ","
            << fixed << setprecision(6) << total_overhead << ","
            << fixed << setprecision(6) << network_ms << ","
            << m.request_bytes << ","
            << m.response_bytes << ","
            << communication << ","
            << csv_escape(m.server_pid.empty() ? "unknown" : m.server_pid) << "\n";
    }

    if (!out)
        throw runtime_error("failed while writing metrics csv: " + out_path.string());
    return out_path;
}

static ModuleMetrics registration_cs(const string &host, int port, const string &identity, const string &password)
{
    ModuleMetrics metrics{"Registration"};
    auto module_start = chrono::high_resolution_clock::now();
    cout << "*********************************** CS Registration Phase *********************************" << endl;

    element_t r, h, alpha, beta;
    element_init_Zr(r, pairing);
    element_random(r);
    element_init_G1(h, pairing);
    element_init_G1(alpha, pairing);
    element_init_G1(beta, pairing);

    string psw_id_str = identity + password;
    element_from_hash(h, (void *)psw_id_str.c_str(), psw_id_str.length());
    element_pow_zn(alpha, h, r);

    auto oprf = cs::request_timed(host, port, "REG_OPRF", {{"alpha", element_to_string(alpha)}});
    metrics.add_request(oprf);
    if (element_set_str(beta, cs::require_field(oprf.message, "beta").c_str(), 10) == 0)
        throw runtime_error("failed to parse beta");

    element_t r_inverse, beta_r_inverse, seed, rho, sk_u, pk_u;
    element_init_Zr(r_inverse, pairing);
    element_invert(r_inverse, r);
    element_init_G1(beta_r_inverse, pairing);
    element_pow_zn(beta_r_inverse, beta, r_inverse);

    string pwd_beta = password + element_to_string(beta_r_inverse);
    element_init_G1(seed, pairing);
    element_from_hash(seed, (void *)pwd_beta.c_str(), pwd_beta.length());
    string seed_str = element_to_string(seed);
    save_string_to_file(seed_str, "../Storage/seed.txt");

    string id_seed = identity + seed_str;
    element_init_G1(rho, pairing);
    element_from_hash(rho, (void *)id_seed.c_str(), id_seed.length());

    string seed_sign = seed_str + "Sign";
    element_init_Zr(sk_u, pairing);
    element_from_hash(sk_u, (void *)seed_sign.c_str(), seed_sign.length());
    element_init_G1(pk_u, pairing);
    element_pow_zn(pk_u, g, sk_u);

    string rho_str = element_to_string(rho);
    string pk_u_str = element_to_string(pk_u);
    save_element_G1("../Storage/rho.txt", rho);
    save_element_G1("../Storage/user_public_key.txt", pk_u);

    auto finish = cs::request_timed(host, port, "REG_FINISH", {{"rho", rho_str}, {"pk_u", pk_u_str}});
    metrics.add_request(finish);
    save_string_to_file(cs::require_field(finish.message, "sigma_rho"), "../Storage/sigma_rho");

    element_clear(r);
    element_clear(h);
    element_clear(alpha);
    element_clear(beta);
    element_clear(r_inverse);
    element_clear(beta_r_inverse);
    element_clear(seed);
    element_clear(rho);
    element_clear(sk_u);
    element_clear(pk_u);

    auto module_end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(module_end - module_start).count() - metrics.rtt_ms;
    print_metrics(metrics);
    return metrics;
}

static ModuleMetrics login_cs(const string &host, int port, const string &identity, const string &password)
{
    ModuleMetrics metrics{"Login"};
    auto module_start = chrono::high_resolution_clock::now();
    cout << "*********************************** CS Login Phase *********************************" << endl;

    element_t rho;
    element_init_G1(rho, pairing);
    if (!Load_element_G1("../Storage/rho.txt", rho))
        throw runtime_error("failed to load rho");
    string rho_str = element_to_string(rho);

    element_t r, h, alpha, beta;
    element_init_Zr(r, pairing);
    element_random(r);
    element_init_G1(h, pairing);
    element_init_G1(alpha, pairing);
    element_init_G1(beta, pairing);

    string psw_id_str = identity + password;
    element_from_hash(h, (void *)psw_id_str.c_str(), psw_id_str.length());
    element_pow_zn(alpha, h, r);

    auto oprf = cs::request_timed(host, port, "LOGIN_OPRF", {{"alpha", element_to_string(alpha)}});
    metrics.add_request(oprf);
    if (element_set_str(beta, cs::require_field(oprf.message, "beta").c_str(), 10) == 0)
        throw runtime_error("failed to parse beta");

    element_t r_inverse, beta_r_inverse, seed, sk_u;
    element_init_Zr(r_inverse, pairing);
    element_invert(r_inverse, r);
    element_init_G1(beta_r_inverse, pairing);
    element_pow_zn(beta_r_inverse, beta, r_inverse);

    string pwd_beta = password + element_to_string(beta_r_inverse);
    element_init_G1(seed, pairing);
    element_from_hash(seed, (void *)pwd_beta.c_str(), pwd_beta.length());

    string seed_str = element_to_string(seed);
    string seed_sign = seed_str + "Sign";
    element_init_Zr(sk_u, pairing);
    element_from_hash(sk_u, (void *)seed_sign.c_str(), seed_sign.length());

    auto challenge = cs::request_timed(host, port, "LOGIN_CHALLENGE", {});
    metrics.add_request(challenge);
    string sid = cs::require_field(challenge.message, "sid");
    string Y_str = cs::require_field(challenge.message, "Y");
    string sigma_s = cs::require_field(challenge.message, "sigma_s");

    element_t Y, pk_s;
    element_init_G1(Y, pairing);
    element_init_G1(pk_s, pairing);
    set_g1_from_string(Y, Y_str);
    if (!Load_element_G1("../Storage/server_public_key.txt", pk_s))
        throw runtime_error("failed to load server public key");
    if (!Verify(Y_str, sigma_s, pk_s))
        throw runtime_error("server signature verification failed");

    element_t x, X, gxy, user_k_se;
    element_init_Zr(x, pairing);
    element_random(x);
    element_init_G1(X, pairing);
    element_pow_zn(X, g, x);

    string X_str = element_to_string(X);
    string user_signed = X_str + Y_str + sigma_s;
    string sigma_u = Sign(user_signed, sk_u);

    element_init_G1(gxy, pairing);
    element_pow_zn(gxy, Y, x);
    string user_seed = sigma_s + sigma_u + X_str + Y_str + element_to_string(gxy);

    element_init_G1(user_k_se, pairing);
    element_from_hash(user_k_se, (void *)user_seed.c_str(), user_seed.length());
    string user_k_se_str = element_to_string(user_k_se);

    auto finish = cs::request_timed(host, port, "LOGIN_FINISH",
                                    {{"sid", sid}, {"rho", rho_str}, {"X", X_str}, {"sigma_u", sigma_u}});
    metrics.add_request(finish);
    string server_k_se = cs::require_field(finish.message, "k_se");
    cout << (user_k_se_str == server_k_se ? "CS login finished." : "Session key mismatch.") << endl;

    element_clear(rho);
    element_clear(r);
    element_clear(h);
    element_clear(alpha);
    element_clear(beta);
    element_clear(r_inverse);
    element_clear(beta_r_inverse);
    element_clear(seed);
    element_clear(sk_u);
    element_clear(Y);
    element_clear(pk_s);
    element_clear(x);
    element_clear(X);
    element_clear(gxy);
    element_clear(user_k_se);

    auto module_end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(module_end - module_start).count() - metrics.rtt_ms;
    print_metrics(metrics);
    return metrics;
}

static ModuleMetrics upload_cs(const string &host, int port, int n, int start, const string &module_name = "Upload")
{
    ModuleMetrics metrics{module_name};
    metrics.file_count = n;
    metrics.operation_files = n - start;
    metrics.uploaded_files = n - start;
    auto module_start = chrono::high_resolution_clock::now();
    cout << "*********************************** CS Upload Phase *********************************" << endl;

    if (start < 0 || start > n)
        throw runtime_error("invalid upload start");
    ensure_test_dataset(n);
    vector<unsigned char> key = derive_dek_key();
    auto origin_files = sorted_files("../File/Origin");
    if (static_cast<int>(origin_files.size()) < n)
        throw runtime_error("../File/Origin does not have enough files");

    map<string, string> fields;
    fields["n"] = to_string(n);
    fields["start"] = to_string(start);
    fs::create_directories("../File/Cipher");
    fs::create_directories("../File/Tag");

    vector<string> tags;
    tags.reserve(n);
    for (int i = 0; i < start; ++i)
    {
        string name = origin_files[i].filename().string();
        tags.push_back(read_binary_string(fs::path("../File/Tag") / (name + ".tag")));
    }

    for (int i = start; i < n; ++i)
    {
        string name = origin_files[i].filename().string();
        auto [cipher, tag] = encrypt_file_payload(origin_files[i], key);
        fields["name_" + to_string(i)] = name;
        fields["cipher_" + to_string(i)] = cipher;
        fields["tag_" + to_string(i)] = tag;
        write_binary_string(fs::path("../File/Cipher") / name, cipher);
        write_binary_string(fs::path("../File/Tag") / (name + ".tag"), tag);
        tags.push_back(tag);
    }
    if (static_cast<int>(tags.size()) != n)
        throw runtime_error("upload tag count mismatch");

    HVC hvc(n, pairing);
    vector<element_t> m(n);
    for (int i = 0; i < n; ++i)
    {
        element_init_Zr(m[i], pairing);
        element_from_hash(m[i], (void *)tags[i].data(), tags[i].size());
    }
    element_t C, r;
    element_init_G1(C, pairing);
    element_init_Zr(r, pairing);
    hvc.commit(m.data(), n, C, r);
    save_local_commitment(C);
    save_local_randomness(r);
    fields["r"] = element_to_string(r);

    auto response = cs::request_timed(host, port, "UPLOAD", fields);
    metrics.add_request(response);
    cout << "CS upload finished. files=" << cs::require_field(response.message, "files")
         << " uploaded_files=" << cs::require_field(response.message, "uploaded_files") << endl;

    for (int i = 0; i < n; ++i)
        element_clear(m[i]);
    element_clear(C);
    element_clear(r);

    auto module_end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(module_end - module_start).count() - metrics.rtt_ms;
    print_metrics(metrics);
    return metrics;
}

static ModuleMetrics single_query_cs(const string &host, int port, int n, int count, const string &module_name = "SingleQuery")
{
    ModuleMetrics metrics{module_name};
    metrics.file_count = n;
    metrics.operation_files = count;
    auto module_start = chrono::high_resolution_clock::now();
    cout << "*********************************** CS SingleQuery Phase *********************************" << endl;

    HVC hvc(n, pairing);
    vector<unsigned char> key = derive_dek_key();
    string C = read_local_commitment();
    for (int i = 0; i < count; ++i)
    {
        int index = i % n;
        auto response = cs::request_timed(host, port, "SINGLE_QUERY", {{"n", to_string(n)}, {"index", to_string(index)}});
        metrics.add_request(response);

        string name = cs::require_field(response.message, "name");
        string cipher = cs::require_field(response.message, "cipher");
        string tag = cs::require_field(response.message, "tag");
        string proof = cs::require_field(response.message, "proof");
        if (!verify_proof_from_payload(hvc, C, proof, tag, index))
            cerr << "Warning: single query proof verification failed. index=" << index << endl;
        decrypt_payload_to_file(name, cipher, tag, "../File/SingleQuery", key);
    }
    cout << "CS single query finished. count=" << count << endl;

    auto module_end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(module_end - module_start).count() - metrics.rtt_ms;
    print_metrics(metrics);
    return metrics;
}

static ModuleMetrics batch_query_cs(const string &host, int port, int n, int count, const string &module_name = "BatchQuery")
{
    ModuleMetrics metrics{module_name};
    metrics.file_count = n;
    metrics.operation_files = count;
    auto module_start = chrono::high_resolution_clock::now();
    cout << "*********************************** CS BatchQuery Phase *********************************" << endl;

    map<string, string> fields;
    fields["n"] = to_string(n);
    fields["count"] = to_string(count);
    for (int i = 0; i < count; ++i)
        fields["index_" + to_string(i)] = to_string(i);

    auto response = cs::request_timed(host, port, "BATCH_QUERY", fields);
    metrics.add_request(response);
    HVC hvc(n, pairing);
    vector<unsigned char> key = derive_dek_key();
    string C = read_local_commitment();
    vector<string> tags;
    vector<int> indices;
    tags.reserve(count);
    indices.reserve(count);

    for (int i = 0; i < count; ++i)
    {
        string k = to_string(i);
        int index = stoi(cs::require_field(response.message, "index_" + k));
        string name = cs::require_field(response.message, "name_" + k);
        string cipher = cs::require_field(response.message, "cipher_" + k);
        string tag = cs::require_field(response.message, "tag_" + k);
        indices.push_back(index);
        tags.push_back(tag);
        decrypt_payload_to_file(name, cipher, tag, "../File/BatchQuery", key);
    }
    string proof_agg = cs::require_field(response.message, "proof_agg");
    if (!verify_aggregate_proof_from_payload(hvc, C, proof_agg, tags, indices))
        cerr << "Warning: batch query aggregate proof verification failed." << endl;
    cout << "CS batch query finished. count=" << count << endl;

    auto module_end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(module_end - module_start).count() - metrics.rtt_ms;
    print_metrics(metrics);
    return metrics;
}

static ModuleMetrics update_cs(const string &host, int port, int n, int update_count, const string &module_name = "Update")
{
    ModuleMetrics metrics{module_name};
    metrics.file_count = n;
    metrics.operation_files = update_count;
    metrics.updated_files = update_count;
    auto module_start = chrono::high_resolution_clock::now();
    cout << "*********************************** CS Update Phase *********************************" << endl;

    if (update_count < 0 || update_count > n)
        throw runtime_error("invalid update count");
    vector<unsigned char> key = derive_dek_key();
    HVC hvc(n, pairing);
    string C_old_bin = read_local_commitment();

    map<string, string> query_fields;
    query_fields["n"] = to_string(n);
    query_fields["count"] = to_string(update_count);
    query_fields["proof_mode"] = "individual";
    for (int i = 0; i < update_count; ++i)
        query_fields["index_" + to_string(i)] = to_string(i);
    auto old_payload = cs::request_timed(host, port, "BATCH_QUERY", query_fields);
    metrics.add_request(old_payload);

    map<string, string> fields;
    fields["n"] = to_string(n);
    fields["count"] = to_string(update_count);
    fs::create_directories("../File/Cipher");
    fs::create_directories("../File/Tag");

    auto origin_files = sorted_files("../File/Origin");
    vector<element_t> delta_vec(n);
    for (int i = 0; i < n; ++i)
    {
        element_init_Zr(delta_vec[i], pairing);
        element_set0(delta_vec[i]);
    }

    for (int i = 0; i < update_count; ++i)
    {
        int index = i;
        string response_key = to_string(i);
        string old_name = cs::require_field(old_payload.message, "name_" + response_key);
        string old_cipher = cs::require_field(old_payload.message, "cipher_" + response_key);
        string old_tag = cs::require_field(old_payload.message, "tag_" + response_key);
        string old_proof = cs::require_field(old_payload.message, "proof_" + response_key);
        if (!verify_proof_from_payload(hvc, C_old_bin, old_proof, old_tag, index))
            throw runtime_error("old proof verification failed before update: " + old_name);
        decrypt_payload_to_file(old_name, old_cipher, old_tag, "../File/Update/Old", key);

        string name = old_name;
        fs::path update_path = fs::path("../File/Update/Origin") / name;
        if (!fs::exists(update_path))
        {
            if (index < 0 || index >= static_cast<int>(origin_files.size()))
                throw runtime_error("no update file and origin fallback is out of range");
            update_path = origin_files[index];
            name = update_path.filename().string();
        }

        auto [cipher, tag] = encrypt_file_payload(update_path, key);

        element_t old_tag_elem, new_tag_elem, delta_tag;
        element_init_Zr(old_tag_elem, pairing);
        element_init_Zr(new_tag_elem, pairing);
        element_init_Zr(delta_tag, pairing);
        element_from_hash(old_tag_elem, (void *)old_tag.data(), old_tag.size());
        element_from_hash(new_tag_elem, (void *)tag.data(), tag.size());
        element_sub(delta_tag, new_tag_elem, old_tag_elem);
        element_set(delta_vec[index], delta_tag);

        string k = to_string(i);
        fields["index_" + k] = to_string(index);
        fields["name_" + k] = name;
        fields["cipher_" + k] = cipher;
        fields["tag_" + k] = tag;
        fields["delta_" + k] = element_to_string(delta_tag);

        write_binary_string(fs::path("../File/Cipher") / name, cipher);
        write_binary_string(fs::path("../File/Tag") / (name + ".tag"), tag);

        element_clear(old_tag_elem);
        element_clear(new_tag_elem);
        element_clear(delta_tag);
    }

    element_t C_old, C_delta, C_new, r_delta, r_old, r_new;
    element_init_G1(C_old, pairing);
    element_init_G1(C_delta, pairing);
    element_init_Zr(r_delta, pairing);
    element_init_Zr(r_old, pairing);
    element_init_Zr(r_new, pairing);
    set_g1_from_compressed_string(C_old, C_old_bin);
    if (!load_element_Zr("../File/Commit/r.dat", r_old))
        throw runtime_error("failed to load local commitment randomness");
    hvc.commit(delta_vec.data(), n, C_delta, r_delta);
    hvc.comHom(C_old, C_delta, C_new);
    element_add(r_new, r_old, r_delta);
    fields["r_delta"] = element_to_string(r_delta);

    auto response = cs::request_timed(host, port, "UPDATE", fields);
    metrics.add_request(response);
    save_local_commitment(C_new);
    save_local_randomness(r_new);
    cout << "CS update finished. updated_files="
         << cs::require_field(response.message, "updated_files") << endl;

    if (update_count > 0)
    {
        mt19937 rng(static_cast<unsigned int>(chrono::high_resolution_clock::now().time_since_epoch().count()));
        uniform_int_distribution<int> dist(0, update_count - 1);
        int verify_index = dist(rng);
        auto verify_response = cs::request_timed(host, port, "SINGLE_QUERY",
                                                 {{"n", to_string(n)}, {"index", to_string(verify_index)}});
        metrics.add_request(verify_response);
        string name = cs::require_field(verify_response.message, "name");
        string cipher = cs::require_field(verify_response.message, "cipher");
        string tag = cs::require_field(verify_response.message, "tag");
        string proof = cs::require_field(verify_response.message, "proof");
        string C_new_bin = read_local_commitment();
        if (!verify_proof_from_payload(hvc, C_new_bin, proof, tag, verify_index))
            throw runtime_error("post-update proof verification failed: " + name);
        decrypt_payload_to_file(name, cipher, tag, "../File/Update/Verified", key);
        cout << "CS update verification finished. index=" << verify_index << " file=" << name << endl;
    }

    for (int i = 0; i < n; ++i)
        element_clear(delta_vec[i]);
    element_clear(C_old);
    element_clear(C_delta);
    element_clear(C_new);
    element_clear(r_delta);
    element_clear(r_old);
    element_clear(r_new);

    auto module_end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(module_end - module_start).count() - metrics.rtt_ms;
    print_metrics(metrics);
    return metrics;
}

int main(int argc, char **argv)
{
    string host = argc > 1 ? argv[1] : cs::DEFAULT_HOST;
    int port = argc > 2 ? stoi(argv[2]) : cs::DEFAULT_PORT;
    string identity = argc > 3 ? argv[3] : "15926254568";
    string password = argc > 4 ? argv[4] : "19880532Tom";
    int max_files = argc > 5 ? stoi(argv[5]) : 600;
    int upload_step = argc > 6 ? stoi(argv[6]) : 100;
    if (max_files <= 0 || upload_step <= 0)
        throw runtime_error("max_files and upload_step must be positive");

    sysInitial();
    cout << "HRACS client target=" << host << ":" << port << endl;
    cout << "HRACS benchmark max_files=" << max_files
         << " upload_step=" << upload_step
         << " file_size_bytes=" << TEST_FILE_BYTES << endl;

    vector<int> upload_counts = experiment_counts(max_files, upload_step, 1);

    int previous_total = 0;
    vector<ModuleMetrics> upload_metrics;
    for (int total : upload_counts)
    {
        int upload_start = previous_total <= total ? previous_total : 0;
        cout << endl
             << "==================== CS Upload files=" << total
             << " size=1MB upload_start=" << upload_start
             << " upload_count=" << (total - upload_start) << " ====================" << endl;
        ModuleMetrics upload = upload_cs(host, port, total, upload_start);
        upload.file_count = total;
        upload.operation_files = total;
        upload.uploaded_files = total;
        upload_metrics.push_back(upload);
        previous_total = total;
    }

    vector<ReportRow> rows;

    for (size_t i = 0; i < upload_metrics.size(); ++i)
        rows.push_back({i == 0 ? "Upload" : "", file_number_for(upload_metrics[i]), upload_metrics[i]});

    cout << endl
         << "==================== CS Final Metrics Summary ====================" << endl;
    cout << "Module\tFileNumber\tClient(ms)\tServer(ms)\tNetwork(ms)\tComm(bytes)" << endl;
    for (const auto &row : rows)
    {
        const ModuleMetrics &m = row.metrics;
        cout << (row.module.empty() ? m.name : row.module) << "\t"
             << row.file_number << "\t"
             << m.client_ms << "\t"
             << m.server_ms << "\t"
             << max(0.0, m.rtt_ms - m.server_ms) << "\t"
             << (m.request_bytes + m.response_bytes) << endl;
    }
    cout << "==================================================================" << endl;
    fs::path csv_path = write_metrics_csv(rows);
    cout << "CS metrics CSV saved to " << csv_path << endl;
    return 0;
}
