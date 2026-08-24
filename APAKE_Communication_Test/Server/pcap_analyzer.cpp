#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

struct Row
{
    string scheme;
    uint32_t users = 0;
    int trial = 0;
    uint16_t local_port = 0;
    double latency_ms = 0.0;
    uint64_t request_bytes = 0;
    uint64_t response_bytes = 0;
    uint64_t application_bytes = 0;
    uint64_t tcp_segs_out = 0;
    uint64_t tcp_segs_in = 0;
    uint64_t tcp_total_retrans = 0;
    uint64_t tcp_bytes_retrans = 0;
    uint64_t wire_tx_bytes = 0;
    uint64_t wire_rx_bytes = 0;
    uint64_t wire_tx_packets = 0;
    uint64_t wire_rx_packets = 0;
    uint64_t pcap_retransmitted_packets = 0;
    uint64_t pcap_retransmitted_payload_bytes = 0;
    bool tx_sequence_seen = false;
    bool rx_sequence_seen = false;
    uint32_t tx_max_sequence_end = 0;
    uint32_t rx_max_sequence_end = 0;
};

static vector<string> split(const string &line)
{
    vector<string> fields;
    string field;
    istringstream input(line);
    while (getline(input, field, ','))
        fields.push_back(field);
    return fields;
}

static uint16_t be16(const unsigned char *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

static uint32_t be32(const unsigned char *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

static uint32_t read32(const unsigned char *p, bool little)
{
    if (little)
        return static_cast<uint32_t>(p[0]) |
               (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

static vector<Row> read_rows(const string &path)
{
    ifstream input(path);
    if (!input)
        throw runtime_error("cannot open " + path);
    string line;
    getline(input, line);
    vector<Row> rows;
    while (getline(input, line))
    {
        if (line.empty())
            continue;
        vector<string> f = split(line);
        if (f.size() != 12)
            throw runtime_error("invalid raw CSV row: " + line);
        Row row;
        row.scheme = f[0];
        row.users = static_cast<uint32_t>(stoul(f[1]));
        row.trial = stoi(f[2]);
        row.local_port = static_cast<uint16_t>(stoul(f[3]));
        row.latency_ms = stod(f[4]);
        row.request_bytes = stoull(f[5]);
        row.response_bytes = stoull(f[6]);
        row.application_bytes = stoull(f[7]);
        row.tcp_segs_out = stoull(f[8]);
        row.tcp_segs_in = stoull(f[9]);
        row.tcp_total_retrans = stoull(f[10]);
        row.tcp_bytes_retrans = stoull(f[11]);
        rows.push_back(row);
    }
    return rows;
}

static void add_pcap(const string &path, uint16_t server_port, vector<Row> &rows)
{
    ifstream input(path, ios::binary);
    if (!input)
        throw runtime_error("cannot open " + path);
    unsigned char global[24];
    input.read(reinterpret_cast<char *>(global), sizeof(global));
    if (input.gcount() != static_cast<streamsize>(sizeof(global)))
        throw runtime_error("truncated pcap header");

    bool little = false;
    if (global[0] == 0xd4 && global[1] == 0xc3 && global[2] == 0xb2 && global[3] == 0xa1)
        little = true;
    else if (!(global[0] == 0xa1 && global[1] == 0xb2 && global[2] == 0xc3 && global[3] == 0xd4))
        throw runtime_error("unsupported pcap format; use tcpdump without pcapng");
    uint32_t link_type = read32(global + 20, little);
    if (link_type != 1)
        throw runtime_error("capture must use an Ethernet interface (pcap link type 1)");

    map<uint16_t, size_t> active_connection;
    size_t next_row = 0;

    unsigned char record[16];
    while (input.read(reinterpret_cast<char *>(record), sizeof(record)))
    {
        uint32_t incl_len = read32(record + 8, little);
        uint32_t orig_len = read32(record + 12, little);
        vector<unsigned char> packet(incl_len);
        input.read(reinterpret_cast<char *>(packet.data()), incl_len);
        if (input.gcount() != static_cast<streamsize>(incl_len))
            throw runtime_error("truncated pcap packet");
        if (packet.size() < 14)
            continue;

        size_t ip_offset = 14;
        uint16_t ether_type = be16(packet.data() + 12);
        while ((ether_type == 0x8100 || ether_type == 0x88a8) && packet.size() >= ip_offset + 4)
        {
            ether_type = be16(packet.data() + ip_offset + 2);
            ip_offset += 4;
        }
        if (ether_type != 0x0800 || packet.size() < ip_offset + 20)
            continue;
        size_t ip_header = static_cast<size_t>(packet[ip_offset] & 0x0f) * 4;
        if (ip_header < 20 || packet.size() < ip_offset + ip_header + 20)
            continue;
        if (packet[ip_offset + 9] != 6)
            continue;
        size_t tcp_offset = ip_offset + ip_header;
        uint16_t source = be16(packet.data() + tcp_offset);
        uint16_t destination = be16(packet.data() + tcp_offset + 2);
        uint8_t tcp_flags = packet[tcp_offset + 13];
        size_t tcp_header = static_cast<size_t>(packet[tcp_offset + 12] >> 4) * 4;
        uint16_t ip_total = be16(packet.data() + ip_offset + 2);
        if (tcp_header < 20 || ip_total < ip_header + tcp_header)
            continue;
        uint32_t payload_length = ip_total - static_cast<uint32_t>(ip_header + tcp_header);
        uint32_t sequence = be32(packet.data() + tcp_offset + 4);

        uint16_t client_port = 0;
        bool client_to_server = false;
        if (destination == server_port)
        {
            client_port = source;
            client_to_server = true;
        }
        else if (source == server_port)
        {
            client_port = destination;
        }
        else
        {
            continue;
        }
        if (client_to_server && (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0)
        {
            if (next_row < rows.size() && rows[next_row].local_port == client_port)
            {
                active_connection[client_port] = next_row++;
            }
            else if (active_connection.find(client_port) == active_connection.end())
            {
                continue;
            }
        }
        auto found = active_connection.find(client_port);
        if (found == active_connection.end())
            continue;
        Row &row = rows[found->second];
        if (client_to_server)
        {
            row.wire_tx_bytes += orig_len;
            ++row.wire_tx_packets;
        }
        else
        {
            row.wire_rx_bytes += orig_len;
            ++row.wire_rx_packets;
        }
        if (payload_length > 0)
        {
            bool &seen = client_to_server ? row.tx_sequence_seen : row.rx_sequence_seen;
            uint32_t &max_end = client_to_server ? row.tx_max_sequence_end : row.rx_max_sequence_end;
            uint32_t end = sequence + payload_length;
            if (seen && sequence < max_end)
            {
                uint32_t overlap_end = min(end, max_end);
                if (overlap_end > sequence)
                {
                    ++row.pcap_retransmitted_packets;
                    row.pcap_retransmitted_payload_bytes += overlap_end - sequence;
                }
            }
            if (!seen || end > max_end)
                max_end = end;
            seen = true;
        }
    }
    if (next_row != rows.size())
        throw runtime_error("pcap contains " + to_string(next_row) +
                            " matched connections, expected " + to_string(rows.size()));
}

static pair<double, double> mean_stddev(const vector<double> &values)
{
    if (values.empty())
        return {0.0, 0.0};
    double mean = 0.0;
    for (double value : values)
        mean += value;
    mean /= values.size();
    if (values.size() == 1)
        return {mean, 0.0};
    double variance = 0.0;
    for (double value : values)
        variance += (value - mean) * (value - mean);
    variance /= values.size() - 1;
    return {mean, sqrt(variance)};
}

static void write_wire_raw(const string &path, const vector<Row> &rows)
{
    ofstream out(path);
    if (!out)
        throw runtime_error("cannot write " + path);
    out << "scheme,number_of_users,trial,local_port,latency_ms,application_bytes,"
           "wire_tx_bytes,wire_rx_bytes,wire_total_bytes,wire_total_KB,"
           "wire_tx_packets,wire_rx_packets,wire_total_packets,"
           "client_tcp_total_retrans,client_tcp_bytes_retrans,"
           "pcap_retransmitted_packets,pcap_retransmitted_payload_bytes\n";
    out << fixed << setprecision(6);
    for (const Row &row : rows)
    {
        uint64_t wire_bytes = row.wire_tx_bytes + row.wire_rx_bytes;
        uint64_t packets = row.wire_tx_packets + row.wire_rx_packets;
        out << row.scheme << ',' << row.users << ',' << row.trial << ',' << row.local_port
            << ',' << row.latency_ms << ',' << row.application_bytes << ','
            << row.wire_tx_bytes << ',' << row.wire_rx_bytes << ',' << wire_bytes << ','
            << static_cast<double>(wire_bytes) / 1024.0 << ','
            << row.wire_tx_packets << ',' << row.wire_rx_packets << ',' << packets << ','
            << row.tcp_total_retrans << ',' << row.tcp_bytes_retrans << ','
            << row.pcap_retransmitted_packets << ','
            << row.pcap_retransmitted_payload_bytes << '\n';
    }
}

static void write_summary(const string &path, const vector<Row> &rows)
{
    map<pair<string, uint32_t>, vector<const Row *>> groups;
    for (const Row &row : rows)
        groups[{row.scheme, row.users}].push_back(&row);
    ofstream out(path);
    if (!out)
        throw runtime_error("cannot write " + path);
    out << "scheme,Number of user,trials,application_mean_KB,application_stddev_KB,"
           "wire_mean_KB,wire_stddev_KB,latency_mean_ms,latency_stddev_ms,"
           "packets_mean,packets_stddev,pcap_retransmitted_packets_mean,"
           "pcap_retransmitted_packets_stddev,pcap_retransmitted_payload_bytes_mean,"
           "pcap_retransmitted_payload_bytes_stddev\n";
    out << fixed << setprecision(6);
    for (const auto &entry : groups)
    {
        vector<double> application, wire, latency, packets, retransmissions, retransmitted_bytes;
        for (const Row *row : entry.second)
        {
            application.push_back(static_cast<double>(row->application_bytes) / 1024.0);
            wire.push_back(static_cast<double>(row->wire_tx_bytes + row->wire_rx_bytes) / 1024.0);
            latency.push_back(row->latency_ms);
            packets.push_back(static_cast<double>(row->wire_tx_packets + row->wire_rx_packets));
            retransmissions.push_back(static_cast<double>(row->pcap_retransmitted_packets));
            retransmitted_bytes.push_back(
                static_cast<double>(row->pcap_retransmitted_payload_bytes));
        }
        auto app_stat = mean_stddev(application);
        auto wire_stat = mean_stddev(wire);
        auto latency_stat = mean_stddev(latency);
        auto packet_stat = mean_stddev(packets);
        auto retrans_stat = mean_stddev(retransmissions);
        auto retrans_bytes_stat = mean_stddev(retransmitted_bytes);
        out << entry.first.first << ',' << entry.first.second << ',' << entry.second.size()
            << ',' << app_stat.first << ',' << app_stat.second
            << ',' << wire_stat.first << ',' << wire_stat.second
            << ',' << latency_stat.first << ',' << latency_stat.second
            << ',' << packet_stat.first << ',' << packet_stat.second
            << ',' << retrans_stat.first << ',' << retrans_stat.second
            << ',' << retrans_bytes_stat.first << ',' << retrans_bytes_stat.second << '\n';
    }
}

int main(int argc, char **argv)
{
    if (argc != 6)
    {
        cerr << "Usage: " << argv[0]
             << " capture.pcap raw.csv wire_raw.csv summary.csv server_port\n";
        return 2;
    }
    vector<Row> rows = read_rows(argv[2]);
    add_pcap(argv[1], static_cast<uint16_t>(stoul(argv[5])), rows);
    for (const Row &row : rows)
    {
        if (row.wire_tx_packets == 0 || row.wire_rx_packets == 0)
            throw runtime_error("pcap has no complete frame set for local port " +
                                to_string(row.local_port));
    }
    write_wire_raw(argv[3], rows);
    write_summary(argv[4], rows);
    cout << "Wire raw CSV written to " << argv[3] << '\n';
    cout << "Summary CSV written to " << argv[4] << '\n';
    return 0;
}
