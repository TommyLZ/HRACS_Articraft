#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <linux/tcp.h>
#include <string>
#include <vector>
#include <unistd.h>

#include "protocol.h"

using namespace std;
namespace fs = std::filesystem;

struct Measurement
{
    string scheme;
    uint32_t users = 0;
    int trial = 0;
    uint16_t local_port = 0;
    double latency_ms = 0.0;
    size_t request_bytes = 0;
    size_t response_bytes = 0;
    uint32_t tcp_segs_out = 0;
    uint32_t tcp_segs_in = 0;
    uint32_t tcp_total_retrans = 0;
    uint64_t tcp_bytes_retrans = 0;
};

static uint16_t local_port(int fd)
{
    sockaddr_in address{};
    socklen_t length = sizeof(address);
    if (getsockname(fd, reinterpret_cast<sockaddr *>(&address), &length) != 0)
        throw runtime_error("getsockname failed");
    return ntohs(address.sin_port);
}

static void read_tcp_info(int fd, Measurement &result)
{
    tcp_info info{};
    socklen_t length = sizeof(info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) != 0)
        throw runtime_error("TCP_INFO failed");
    result.tcp_segs_out = info.tcpi_segs_out;
    result.tcp_segs_in = info.tcpi_segs_in;
    result.tcp_total_retrans = info.tcpi_total_retrans;
    result.tcp_bytes_retrans = info.tcpi_bytes_retrans;
}

static Measurement measure(const string &host, int port, uint8_t scheme,
                           uint32_t users, const string &name, int trial)
{
    auto started = chrono::steady_clock::now();
    int fd = wire::connect_socket(host, port);
    Measurement result{name, users, trial};
    result.local_port = local_port(fd);
    if (!wire::send_request(fd, scheme, users, result.request_bytes))
    {
        close(fd);
        throw runtime_error("failed to send request");
    }
    uint8_t status = 0;
    uint64_t payload_size = 0;
    if (!wire::recv_response_header(fd, status, payload_size, result.response_bytes))
    {
        close(fd);
        throw runtime_error("failed to receive response header");
    }
    if (status != 0)
    {
        close(fd);
        throw runtime_error("server returned an error");
    }
    array<unsigned char, 64 * 1024> buffer{};
    uint64_t remaining = payload_size;
    while (remaining > 0)
    {
        size_t chunk = static_cast<size_t>(min<uint64_t>(remaining, buffer.size()));
        if (!wire::recv_all(fd, buffer.data(), chunk, result.response_bytes))
        {
            close(fd);
            throw runtime_error("failed to receive payload");
        }
        remaining -= chunk;
    }
    auto finished = chrono::steady_clock::now();
    result.latency_ms = chrono::duration<double, milli>(finished - started).count();
    read_tcp_info(fd, result);
    close(fd);
    return result;
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
    int port = argc > 2 ? stoi(argv[2]) : 19203;
    int trials = argc > 3 ? stoi(argv[3]) : 10;
    if (trials < 1)
        throw runtime_error("trials must be positive");

    vector<uint32_t> user_counts;
    for (uint32_t users = 2000; users <= 20000; users += 2000)
        user_counts.push_back(users);

    vector<Measurement> results;
    for (uint32_t users : user_counts)
    {
        for (int trial = 1; trial <= trials; ++trial)
            results.push_back(measure(host, port, wire::PIR_BASED, users,
                                      "PIR-based APAKE", trial));
        for (int trial = 1; trial <= trials; ++trial)
            results.push_back(measure(host, port, wire::PIR_FREE, users,
                                      "PIR-free APAKE (Ours)", trial));
    }

    fs::create_directories("../Result");
    string path = "../Result/" + date_stamp() + "_APAKE_Communication_raw.csv";
    ofstream csv(path);
    if (!csv)
        throw runtime_error("cannot write " + path);
    csv << "scheme,number_of_users,trial,local_port,latency_ms,request_bytes,"
           "response_bytes,application_bytes,tcp_segs_out,tcp_segs_in,"
           "client_tcp_total_retrans,client_tcp_bytes_retrans\n";
    csv << fixed << setprecision(6);
    for (const auto &result : results)
    {
        size_t total = result.request_bytes + result.response_bytes;
        csv << result.scheme << ',' << result.users << ',' << result.trial << ','
            << result.local_port << ',' << result.latency_ms << ','
            << result.request_bytes << ',' << result.response_bytes << ',' << total << ','
            << result.tcp_segs_out << ',' << result.tcp_segs_in << ','
            << result.tcp_total_retrans << ',' << result.tcp_bytes_retrans << '\n';
        cout << result.scheme << " users=" << result.users
             << " trial=" << result.trial << '/' << trials
             << " app_bytes=" << total
             << " retrans=" << result.tcp_total_retrans << endl;
    }
    csv.close();

    int fd = wire::connect_socket(host, port);
    size_t stop_bytes = 0;
    wire::send_request(fd, wire::STOP, 0, stop_bytes);
    close(fd);
    cout << "[APAKE Communication Client] Raw CSV written to " << path << endl;
    return 0;
}
