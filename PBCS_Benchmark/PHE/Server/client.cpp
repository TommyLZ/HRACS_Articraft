#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "CSProtocol.h"
#include "Client.h"
#include "PublicParam.h"

using namespace std;
namespace fs = std::filesystem;

extern pairing_t pairing;
extern element_t g;

static constexpr int PHE_ITERATIONS = 5;
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
        ensure_test_file(fs::path("../File/TestMultiple/Origin") / file_name(i), static_cast<unsigned char>(0x21 + i));
        ensure_test_file(fs::path("../File/Update/Origin") / file_name(i), static_cast<unsigned char>(0x83 + i));
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

static void sync_public_parameters(const string &host, int port)
{
    cs::TimedResponse response = cs::request_timed(host, port, "GET_PUBLIC", {});
    blob_to_element(g, cs::require_field(response.message, "g"));
}

struct Session
{
    string cred_cs;
};

static Session login(const string &host, int port, string &psw, string &id, ModuleMetrics &metrics)
{
    Client client(psw, id);
    element_t a;
    element_init_G1(a, pairing);
    client.blindPassword(a);

    cs::TimedResponse harden = cs::request_timed(host, port, "HARDEN", {{"a", element_to_blob(a)}});
    metrics.add_request(harden);

    element_t b, public_key;
    element_init_G1(b, pairing);
    element_init_G1(public_key, pairing);
    blob_to_element(b, cs::require_field(harden.message, "b"));
    blob_to_element(public_key, cs::require_field(harden.message, "public_key"));

    string cred_cs;
    client.CredentialGen(cred_cs, b, a, public_key);

    element_clear(a);
    element_clear(b);
    element_clear(public_key);
    return {cred_cs};
}

static ModuleMetrics login_cs(const string &host, int port, string &psw, string &id)
{
    ModuleMetrics metrics{"Login"};
    auto start = chrono::high_resolution_clock::now();
    login(host, port, psw, id, metrics);
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    return metrics;
}

static ModuleMetrics registration_cs(const string &host, int port, string &psw, string &id)
{
    ModuleMetrics metrics{"Registration"};
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, metrics);
    metrics.add_request(cs::request_timed(host, port, "REGISTER", {{"id", id}, {"cred_cs", session.cred_cs}}));
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    return metrics;
}

static ModuleMetrics key_give_cs(const string &host, int port, string &psw, string &id)
{
    ModuleMetrics metrics{"KeyGive"};
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, metrics);
    metrics.add_request(cs::request_timed(host, port, "ENCRYPT_KEY", {{"id", id}, {"cred_cs", session.cred_cs}}));
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    return metrics;
}

static ModuleMetrics key_take_cs(const string &host, int port, string &psw, string &id)
{
    ModuleMetrics metrics{"KeyTake"};
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, metrics);
    metrics.add_request(cs::request_timed(host, port, "RECOVER_KEY", {{"id", id}, {"cred_cs", session.cred_cs}}));
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    return metrics;
}

static void upload_one_file(const string &host, int port, const string &id, const Session &session,
                            int index, ModuleMetrics &metrics)
{
    string name = file_name(index);
    metrics.add_request(cs::request_timed(host, port, "UPLOAD",
                                          {{"id", id}, {"cred_cs", session.cred_cs}, {"index", to_string(index)}, {"name", file_name(index)}, {"plain", read_binary(fs::path("../File/TestMultiple/Origin") / name)}}));
}

static vector<ModuleMetrics> upload_series_cs(const string &host, int port, string &psw, string &id,
                                              int max_files, int upload_step)
{
    ModuleMetrics running{"Upload100"};
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, running);

    vector<int> checkpoints = experiment_counts(max_files, upload_step, 1);
    size_t next_checkpoint = 0;
    vector<ModuleMetrics> snapshots;
    for (int index = 1; index <= max_files; ++index)
    {
        upload_one_file(host, port, id, session, index, running);
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
            ++next_checkpoint;
        }
    }
    return snapshots;
}

static ModuleMetrics upload_single_cs(const string &host, int port, string &psw, string &id)
{
    ModuleMetrics metrics{"Upload"};
    metrics.file_count = 1;
    metrics.operation_files = 1;
    metrics.uploaded_files = 1;
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, metrics);
    upload_one_file(host, port, id, session, TEST_INDEX, metrics);
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    return metrics;
}

static void prepare_query_file_cs(const string &host, int port, string &psw, string &id)
{
    ModuleMetrics ignored{"PrepareQueryFile"};
    Session session = login(host, port, psw, id, ignored);
    upload_one_file(host, port, id, session, TEST_INDEX, ignored);
}

static ModuleMetrics single_query_cs(const string &host, int port, string &psw, string &id,
                                     int total_files, int operation_files)
{
    ModuleMetrics metrics{"SingleQuery"};
    metrics.file_count = total_files;
    metrics.operation_files = operation_files;
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, metrics);
    for (int index = 1; index <= operation_files; ++index)
    {
        cs::TimedResponse query = cs::request_timed(host, port, "SINGLE_QUERY",
                                                    {{"id", id}, {"cred_cs", session.cred_cs}, {"index", to_string(index)}});
        metrics.add_request(query);
        write_binary(fs::path("../File/TestMultiple/Recover(Single)") / file_name(index),
                     cs::require_field(query.message, "plain"));
    }
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    return metrics;
}

static ModuleMetrics batch_query_cs(const string &host, int port, string &psw, string &id,
                                    int total_files, int operation_files)
{
    ModuleMetrics metrics{"BatchQuery"};
    metrics.file_count = total_files;
    metrics.operation_files = operation_files;
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, metrics);
    for (int index = 1; index <= operation_files; ++index)
    {
        cs::TimedResponse query = cs::request_timed(host, port, "SINGLE_QUERY",
                                                    {{"id", id}, {"cred_cs", session.cred_cs}, {"index", to_string(index)}});
        metrics.add_request(query);
        write_binary(fs::path("../File/TestMultiple/Recover(Batch)") / file_name(index),
                     cs::require_field(query.message, "plain"));
    }
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
    return metrics;
}

static ModuleMetrics update_cs(const string &host, int port, string &psw, string &id,
                               int total_files, int operation_files)
{
    ModuleMetrics metrics{"Update"};
    metrics.file_count = total_files;
    metrics.operation_files = operation_files;
    metrics.updated_files = operation_files;
    auto start = chrono::high_resolution_clock::now();
    Session session = login(host, port, psw, id, metrics);
    for (int index = 1; index <= operation_files; ++index)
    {
        string name = file_name(index);
        metrics.add_request(cs::request_timed(host, port, "UPDATE",
                                              {{"id", id}, {"cred_cs", session.cred_cs}, {"index", to_string(index)}, {"name", name}, {"plain", read_binary(fs::path("../File/Update/Origin") / name)}}));
    }
    auto end = chrono::high_resolution_clock::now();
    metrics.client_ms = chrono::duration<double, milli>(end - start).count() - metrics.rtt_ms;
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
    name << put_time(&local_tm, "%Y%m%d") << "_PHE.csv";
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
    int iterations = argc > 7 ? stoi(argv[7]) : PHE_ITERATIONS;

    if (max_files <= 0 || upload_step <= 0 || iterations <= 0)
        throw runtime_error("max_files, upload_step, and iterations must be positive");

    sysInitial();
    ensure_dataset(max_files);
    sync_public_parameters(host, port);

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

    bool upload_series_done = false;
    for (int i = 0; i < iterations; ++i)
    {
        registration_total.add_iteration(registration_cs(host, port, psw, id));
        login_total.add_iteration(login_cs(host, port, psw, id));
        if (!upload_series_done)
        {
            vector<ModuleMetrics> uploads = upload_series_cs(host, port, psw, id, max_files, upload_step);
            if (uploads.size() != upload_counts.size())
                throw runtime_error("upload series did not produce the expected cumulative metrics");
            for (size_t j = 0; j < uploads.size(); ++j)
                upload_totals[j].add_iteration(uploads[j]);
            upload_series_done = true;
        }

        for (size_t j = 0; j < query_counts.size(); ++j)
            single_query_totals[j].add_iteration(single_query_cs(host, port, psw, id, max_files, query_counts[j]));
        for (size_t j = 0; j < batch_counts.size(); ++j)
            batch_query_totals[j].add_iteration(batch_query_cs(host, port, psw, id, max_files, batch_counts[j]));
        for (size_t j = 0; j < update_counts.size(); ++j)
            update_totals[j].add_iteration(update_cs(host, port, psw, id, max_files, update_counts[j]));
    }

    registration_total.average(iterations);
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
    return 0;
}
