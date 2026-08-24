#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

#include "protocol.h"

using namespace std;

static array<unsigned char, wire::PIR_RECORD_BYTES> make_pir_record()
{
    array<unsigned char, wire::PIR_RECORD_BYTES> record{};
    for (size_t i = 0; i < record.size(); ++i)
        record[i] = static_cast<unsigned char>((i * 131 + 17) & 0xff);
    return record;
}

static array<unsigned char, wire::PIR_FREE_TRANSCRIPT_BYTES> make_pir_free_transcript()
{
    array<unsigned char, wire::PIR_FREE_TRANSCRIPT_BYTES> transcript{};
    for (size_t i = 0; i < transcript.size(); ++i)
        transcript[i] = static_cast<unsigned char>((i * 197 + 29) & 0xff);
    return transcript;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? stoi(argv[1]) : 19203;
    int listener = wire::listen_socket(port);
    cout << "[APAKE Communication Server] Listening on port " << port
         << " pid=" << getpid() << endl;

    const auto pir_record = make_pir_record();
    const auto pir_free_transcript = make_pir_free_transcript();
    bool running = true;
    while (running)
    {
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0)
            continue;
        try
        {
            size_t received = 0;
            size_t sent = 0;
            uint8_t scheme = 0;
            uint32_t users = 0;
            if (!wire::recv_request(fd, scheme, users, received))
            {
                close(fd);
                continue;
            }
            if (scheme == wire::STOP)
            {
                running = false;
                close(fd);
                continue;
            }

            uint64_t payload_size = 0;
            if (scheme == wire::PIR_BASED)
                payload_size = static_cast<uint64_t>(users) * pir_record.size();
            else if (scheme == wire::PIR_FREE)
                payload_size = pir_free_transcript.size();
            else
                throw runtime_error("unknown scheme");

            if (!wire::send_response_header(fd, 0, payload_size, sent))
                throw runtime_error("failed to send response header");
            if (scheme == wire::PIR_BASED)
            {
                for (uint32_t i = 0; i < users; ++i)
                {
                    if (!wire::send_all(fd, pir_record.data(), pir_record.size(), sent))
                        throw runtime_error("failed to send PIR record");
                }
            }
            else if (!wire::send_all(fd, pir_free_transcript.data(),
                                     pir_free_transcript.size(), sent))
            {
                throw runtime_error("failed to send PIR-free transcript");
            }
            cout << "[APAKE Communication Server] scheme=" << static_cast<int>(scheme)
                 << " users=" << users << " received=" << received
                 << " sent=" << sent << endl;
        }
        catch (const exception &error)
        {
            cerr << "[APAKE Communication Server] " << error.what() << endl;
        }
        close(fd);
    }
    close(listener);
    return 0;
}
