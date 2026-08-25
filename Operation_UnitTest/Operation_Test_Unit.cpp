#include <iostream>
#include <chrono>
#include <cstdio>
#include <pbc/pbc.h>

using namespace std;
using namespace std::chrono;

int main()
{
    const int TEST_NUM = 1000;

    pbc_param_t param;
    pairing_t pairing;

    pbc_param_init_a_gen(param, 160, 1024);
    pairing_init_pbc_param(pairing, param);

    element_t g, h, gt, x;

    element_init_G1(g, pairing);
    element_init_G1(h, pairing);
    element_init_GT(gt, pairing);
    element_init_Zr(x, pairing);

    element_random(g);
    element_random(h);
    element_random(x);

    element_t hash_elem;
    element_init_G1(hash_elem, pairing);

    char msg[64];

    auto hash_start = steady_clock::now();

    for (int i = 0; i < TEST_NUM; ++i)
    {
        int len = snprintf(
            msg,
            sizeof(msg),
            "Hello PBC Benchmark %d",
            i);

        element_from_hash(
            hash_elem,
            static_cast<void *>(msg),
            len);
    }

    auto hash_end = steady_clock::now();

    double hash_avg_ns =
        duration_cast<nanoseconds>(hash_end - hash_start).count() / static_cast<double>(TEST_NUM);

    element_t exp_result;
    element_init_G1(exp_result, pairing);

    auto exp_start = steady_clock::now();

    for (int i = 0; i < TEST_NUM; ++i)
    {
        element_pow_zn(exp_result, g, x);
    }

    auto exp_end = steady_clock::now();

    double exp_avg_ns =
        duration_cast<nanoseconds>(exp_end - exp_start).count() / static_cast<double>(TEST_NUM);

    auto pair_start = steady_clock::now();

    for (int i = 0; i < TEST_NUM; ++i)
    {
        pairing_apply(gt, g, h, pairing);
    }

    auto pair_end = steady_clock::now();

    double pair_avg_ns =
        duration_cast<nanoseconds>(pair_end - pair_start).count() / static_cast<double>(TEST_NUM);

    cout << "======================================" << endl;
    cout << "Benchmark Results (" << TEST_NUM << " runs)" << endl;
    cout << "Type A parameters: r = 160 bit, q = 1024 bit" << endl;
    cout << "======================================" << endl;

    cout << "Hash-to-G1 : "
         << hash_avg_ns / 1e6 << " ms"
         << " (" << hash_avg_ns / 1e3 << " us)"
         << endl;

    cout << "Exponent   : "
         << exp_avg_ns / 1e6 << " ms"
         << " (" << exp_avg_ns / 1e3 << " us)"
         << endl;

    cout << "Pairing    : "
         << pair_avg_ns / 1e6 << " ms"
         << " (" << pair_avg_ns / 1e3 << " us)"
         << endl;

    element_clear(g);
    element_clear(h);
    element_clear(gt);
    element_clear(x);
    element_clear(hash_elem);
    element_clear(exp_result);

    pairing_clear(pairing);
    pbc_param_clear(param);

    return 0;
}