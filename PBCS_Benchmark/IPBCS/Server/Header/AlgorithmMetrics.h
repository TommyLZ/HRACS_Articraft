#pragma once

#include <cstddef>
#include <filesystem>
#include <string>

namespace algmetrics
{
    struct Estimate
    {
        std::size_t request_bytes = 0;
        std::size_t response_bytes = 0;
        int round_trips = 0;
        std::size_t total_bytes() const { return request_bytes + response_bytes; }
    };

    inline std::size_t file_size_or_zero(const std::filesystem::path &path)
    {
        std::error_code ec;
        auto size = std::filesystem::file_size(path, ec);
        return ec ? 0 : static_cast<std::size_t>(size);
    }

    inline std::string file_prefix(int index)
    {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%03d", index);
        return std::string("Test_") + buf;
    }

    inline Estimate estimate_ipbcs(const std::string &command, int count, int index)
    {
        constexpr std::size_t elem = 128;
        constexpr std::size_t hash = 32;
        constexpr std::size_t id = 16;
        constexpr std::size_t aes_key = 16;
        constexpr std::size_t iv = 256;
        constexpr std::size_t tag = 32;
        Estimate e;

        auto retrieve = [&]()
        {
            e.request_bytes += elem + id + hash + aes_key + tag;
            e.response_bytes += elem + hash + aes_key + tag;
            e.round_trips += 4;
        };

        if (command == "REGISTRATION")
        {
            e.request_bytes += elem + id + hash;
            e.response_bytes += elem;
            e.round_trips += 2;
        }
        else if (command == "LOGIN")
        {
            e.request_bytes += elem + id + hash + aes_key + tag;
            e.response_bytes += elem + hash + aes_key + tag;
            e.round_trips += 8;
        }
        else if (command == "UPLOAD")
        {
            retrieve();
            for (int i = 1; i <= count; ++i)
            {
                auto p = file_prefix(i);
                e.request_bytes += file_size_or_zero("../File/TestMultiple/Cipher/" + p + "_cipher.dat") + iv;
                e.round_trips += 1;
            }
        }
        else if (command == "SINGLE_QUERY")
        {
            retrieve();
            auto p = file_prefix(index);
            e.request_bytes += id + sizeof(index);
            e.response_bytes += file_size_or_zero("../File/TestMultiple/Cipher/" + p + "_cipher.dat") + iv;
            e.round_trips += 1;
        }
        else if (command == "BATCH_QUERY")
        {
            retrieve();
            for (int i = 1; i <= count; ++i)
            {
                auto p = file_prefix(i);
                e.request_bytes += sizeof(i);
                e.response_bytes += file_size_or_zero("../File/TestMultiple/Cipher/" + p + "_cipher.dat") + iv;
            }
            e.round_trips += count;
        }
        else if (command == "UPDATE")
        {
            retrieve();
            auto oldp = file_prefix(index);
            auto newp = file_prefix(11);
            e.request_bytes += sizeof(index);
            e.response_bytes += file_size_or_zero("../File/TestMultiple/Cipher/" + oldp + "_cipher.dat") + iv;
            e.request_bytes += file_size_or_zero("../File/TestMultiple/Cipher(Update)/" + newp + "_cipher.dat") + iv;
            e.round_trips += 2;
        }
        return e;
    }
}
