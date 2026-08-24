#pragma once

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace wire
{

    constexpr uint32_t MAGIC = 0x4150414b;
    constexpr uint8_t STOP = 0;
    constexpr uint8_t PIR_BASED = 1;
    constexpr uint8_t PIR_FREE = 2;
    constexpr size_t REQUEST_BYTES = 9;
    constexpr size_t RESPONSE_HEADER_BYTES = 9;
    constexpr size_t PIR_RECORD_BYTES = 232;
    constexpr size_t PIR_FREE_TRANSCRIPT_BYTES = 1188;

    inline bool send_all(int fd, const void *data, size_t size, size_t &sent)
    {
        const char *cursor = static_cast<const char *>(data);
        while (size > 0)
        {
            ssize_t count = ::send(fd, cursor, size, 0);
            if (count <= 0)
                return false;
            cursor += count;
            size -= static_cast<size_t>(count);
            sent += static_cast<size_t>(count);
        }
        return true;
    }

    inline bool recv_all(int fd, void *data, size_t size, size_t &received)
    {
        char *cursor = static_cast<char *>(data);
        while (size > 0)
        {
            ssize_t count = ::recv(fd, cursor, size, 0);
            if (count <= 0)
                return false;
            cursor += count;
            size -= static_cast<size_t>(count);
            received += static_cast<size_t>(count);
        }
        return true;
    }

    inline uint64_t host_to_network_u64(uint64_t value)
    {
        uint32_t high = htonl(static_cast<uint32_t>(value >> 32));
        uint32_t low = htonl(static_cast<uint32_t>(value & 0xffffffffULL));
        return (static_cast<uint64_t>(low) << 32) | high;
    }

    inline uint64_t network_to_host_u64(uint64_t value)
    {
        uint32_t high = ntohl(static_cast<uint32_t>(value & 0xffffffffULL));
        uint32_t low = ntohl(static_cast<uint32_t>(value >> 32));
        return (static_cast<uint64_t>(high) << 32) | low;
    }

    inline bool send_request(int fd, uint8_t scheme, uint32_t users, size_t &sent)
    {
        unsigned char request[REQUEST_BYTES];
        uint32_t magic = htonl(MAGIC);
        uint32_t count = htonl(users);
        std::memcpy(request, &magic, sizeof(magic));
        request[4] = scheme;
        std::memcpy(request + 5, &count, sizeof(count));
        return send_all(fd, request, sizeof(request), sent);
    }

    inline bool recv_request(int fd, uint8_t &scheme, uint32_t &users, size_t &received)
    {
        unsigned char request[REQUEST_BYTES];
        if (!recv_all(fd, request, sizeof(request), received))
            return false;
        uint32_t magic = 0;
        uint32_t count = 0;
        std::memcpy(&magic, request, sizeof(magic));
        std::memcpy(&count, request + 5, sizeof(count));
        if (ntohl(magic) != MAGIC)
            throw std::runtime_error("invalid request magic");
        scheme = request[4];
        users = ntohl(count);
        return true;
    }

    inline bool send_response_header(int fd, uint8_t status, uint64_t payload_size, size_t &sent)
    {
        unsigned char header[RESPONSE_HEADER_BYTES];
        header[0] = status;
        uint64_t encoded = host_to_network_u64(payload_size);
        std::memcpy(header + 1, &encoded, sizeof(encoded));
        return send_all(fd, header, sizeof(header), sent);
    }

    inline bool recv_response_header(int fd, uint8_t &status, uint64_t &payload_size,
                                     size_t &received)
    {
        unsigned char header[RESPONSE_HEADER_BYTES];
        if (!recv_all(fd, header, sizeof(header), received))
            return false;
        status = header[0];
        uint64_t encoded = 0;
        std::memcpy(&encoded, header + 1, sizeof(encoded));
        payload_size = network_to_host_u64(encoded);
        return true;
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
            throw std::runtime_error("invalid server address");
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

}
