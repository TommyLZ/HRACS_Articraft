#pragma once

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace cs
{
    static constexpr int DEFAULT_PORT = 19201;

    inline std::string hex_encode(const std::string &input)
    {
        std::ostringstream out;
        for (unsigned char c : input)
            out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        return out.str();
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
        uint32_t size = htonl(static_cast<uint32_t>(payload.size()));
        return send_all(fd, &size, sizeof(size)) && send_all(fd, payload.data(), payload.size());
    }

    inline bool recv_frame(int fd, std::string &payload)
    {
        uint32_t net_size = 0;
        if (!recv_all(fd, &net_size, sizeof(net_size)))
            return false;
        uint32_t size = ntohl(net_size);
        payload.assign(size, '\0');
        return size == 0 || recv_all(fd, payload.data(), size);
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
    };

    inline std::string build_message(const std::string &command,
                                     const std::map<std::string, std::string> &fields)
    {
        std::ostringstream out;
        out << command << '\n';
        for (const auto &field : fields)
            out << field.first << '=' << hex_encode(field.second) << '\n';
        return out.str();
    }

    inline Message parse_message(const std::string &payload)
    {
        std::istringstream input(payload);
        Message message;
        if (!std::getline(input, message.command))
            throw std::runtime_error("empty message");
        std::string line;
        while (std::getline(input, line))
        {
            if (line.empty())
                continue;
            size_t pos = line.find('=');
            if (pos == std::string::npos)
                throw std::runtime_error("invalid message field");
            message.fields[line.substr(0, pos)] = hex_decode(line.substr(pos + 1));
        }
        return message;
    }

    inline std::string require_field(const Message &message, const std::string &name)
    {
        auto it = message.fields.find(name);
        if (it == message.fields.end())
            throw std::runtime_error("missing field: " + name);
        return it->second;
    }

    inline int connect_socket(const std::string &host, int port)
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            throw std::runtime_error("socket failed");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<uint16_t>(port));
        if (::inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1)
        {
            ::close(fd);
            throw std::runtime_error("invalid server address: " + host);
        }
        if (::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
        {
            std::string error = std::strerror(errno);
            ::close(fd);
            throw std::runtime_error("connect failed: " + error);
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
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<uint16_t>(port));
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        if (::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
        {
            std::string error = std::strerror(errno);
            ::close(fd);
            throw std::runtime_error("bind failed: " + error);
        }
        if (::listen(fd, 16) != 0)
        {
            ::close(fd);
            throw std::runtime_error("listen failed");
        }
        return fd;
    }

    inline TimedResponse request_timed(const std::string &host, int port,
                                       const std::string &command,
                                       const std::map<std::string, std::string> &fields)
    {
        int fd = connect_socket(host, port);
        std::string request = build_message(command, fields);
        auto start = std::chrono::high_resolution_clock::now();
        if (!send_frame(fd, request))
        {
            ::close(fd);
            throw std::runtime_error("failed to send request");
        }
        std::string response;
        if (!recv_frame(fd, response))
        {
            ::close(fd);
            throw std::runtime_error("failed to receive response");
        }
        auto end = std::chrono::high_resolution_clock::now();
        ::close(fd);
        TimedResponse result;
        result.rtt_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result.message = parse_message(response);
        if (result.message.command == "ERR")
            throw std::runtime_error(require_field(result.message, "message"));
        return result;
    }
}
