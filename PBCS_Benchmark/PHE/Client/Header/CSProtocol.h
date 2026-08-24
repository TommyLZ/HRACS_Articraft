#pragma once

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <chrono>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace cs
{
    static constexpr int DEFAULT_PORT = 19101;
    static constexpr const char *DEFAULT_HOST = "127.0.0.1";

    inline std::string hex_encode(const std::string &input)
    {
        std::ostringstream oss;
        for (unsigned char c : input)
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        return oss.str();
    }

    inline int hex_value(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        throw std::runtime_error("invalid hex character");
    }

    inline std::string hex_decode(const std::string &input)
    {
        if (input.size() % 2 != 0)
            throw std::runtime_error("invalid hex length");

        std::string out;
        out.reserve(input.size() / 2);
        for (size_t i = 0; i < input.size(); i += 2)
            out.push_back(static_cast<char>((hex_value(input[i]) << 4) | hex_value(input[i + 1])));
        return out;
    }

    inline bool send_all(int fd, const void *data, size_t len)
    {
        const char *p = static_cast<const char *>(data);
        while (len > 0)
        {
            ssize_t n = ::send(fd, p, len, 0);
            if (n <= 0)
                return false;
            p += n;
            len -= static_cast<size_t>(n);
        }
        return true;
    }

    inline bool recv_all(int fd, void *data, size_t len)
    {
        char *p = static_cast<char *>(data);
        while (len > 0)
        {
            ssize_t n = ::recv(fd, p, len, 0);
            if (n <= 0)
                return false;
            p += n;
            len -= static_cast<size_t>(n);
        }
        return true;
    }

    inline bool send_frame(int fd, const std::string &payload)
    {
        uint32_t len = htonl(static_cast<uint32_t>(payload.size()));
        return send_all(fd, &len, sizeof(len)) && send_all(fd, payload.data(), payload.size());
    }

    inline bool recv_frame(int fd, std::string &payload)
    {
        uint32_t net_len = 0;
        if (!recv_all(fd, &net_len, sizeof(net_len)))
            return false;

        uint32_t len = ntohl(net_len);
        payload.assign(len, '\0');
        return len == 0 || recv_all(fd, payload.data(), len);
    }

    struct Message
    {
        std::string command;
        std::map<std::string, std::string> fields;
    };

    struct TimedResponse
    {
        Message message;
        double rtt_ms = 0.0;
        size_t request_bytes = 0;
        size_t response_bytes = 0;
    };

    inline std::string build_message(const std::string &command, const std::map<std::string, std::string> &fields)
    {
        std::ostringstream oss;
        oss << command << "\n";
        for (const auto &kv : fields)
            oss << kv.first << "=" << hex_encode(kv.second) << "\n";
        return oss.str();
    }

    inline Message parse_message(const std::string &payload)
    {
        std::istringstream iss(payload);
        Message msg;
        if (!std::getline(iss, msg.command))
            throw std::runtime_error("empty message");

        std::string line;
        while (std::getline(iss, line))
        {
            if (line.empty())
                continue;
            size_t pos = line.find('=');
            if (pos == std::string::npos)
                throw std::runtime_error("invalid field line");
            msg.fields[line.substr(0, pos)] = hex_decode(line.substr(pos + 1));
        }
        return msg;
    }

    inline std::string require_field(const Message &msg, const std::string &name)
    {
        auto it = msg.fields.find(name);
        if (it == msg.fields.end())
            throw std::runtime_error("missing field: " + name);
        return it->second;
    }

    inline int connect_socket(const std::string &host, int port)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            throw std::runtime_error("socket failed");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
        {
            ::close(fd);
            throw std::runtime_error("invalid server address: " + host);
        }

        if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
        {
            ::close(fd);
            throw std::runtime_error("connect failed: " + std::string(std::strerror(errno)));
        }
        return fd;
    }

    inline int listen_socket(int port)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            throw std::runtime_error("socket failed");

        int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
        {
            ::close(fd);
            throw std::runtime_error("bind failed on port " + std::to_string(port) + ": " + std::string(std::strerror(errno)));
        }
        if (::listen(fd, 16) != 0)
        {
            ::close(fd);
            throw std::runtime_error("listen failed");
        }
        return fd;
    }

    inline Message request(const std::string &host, int port, const std::string &command,
                           const std::map<std::string, std::string> &fields)
    {
        int fd = connect_socket(host, port);
        send_frame(fd, build_message(command, fields));

        std::string response_payload;
        if (!recv_frame(fd, response_payload))
        {
            ::close(fd);
            throw std::runtime_error("failed to receive response");
        }
        ::close(fd);

        Message response = parse_message(response_payload);
        if (response.command == "ERR")
            throw std::runtime_error(require_field(response, "message"));
        return response;
    }

    inline TimedResponse request_timed(const std::string &host, int port, const std::string &command,
                                       const std::map<std::string, std::string> &fields)
    {
        std::string request_payload = build_message(command, fields);
        int fd = connect_socket(host, port);

        auto start = std::chrono::high_resolution_clock::now();
        send_frame(fd, request_payload);

        std::string response_payload;
        if (!recv_frame(fd, response_payload))
        {
            ::close(fd);
            throw std::runtime_error("failed to receive response");
        }
        auto end = std::chrono::high_resolution_clock::now();
        ::close(fd);

        TimedResponse out;
        out.rtt_ms = std::chrono::duration<double, std::milli>(end - start).count();
        out.request_bytes = request_payload.size() + sizeof(uint32_t);
        out.response_bytes = response_payload.size() + sizeof(uint32_t);
        out.message = parse_message(response_payload);
        if (out.message.command == "ERR")
            throw std::runtime_error(require_field(out.message, "message"));
        return out;
    }
}
