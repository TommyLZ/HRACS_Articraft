#include <iostream>
#include <chrono>
#include <fstream>
#include <pbc/pbc.h>
#include <cstring>

#include "PublicParam.h"
#include "Registration.h"
#include "Login.h"

using namespace std;
using namespace std::chrono;

int main()
{
    string identity = "15926254568";
    string password = "19880532Tom";

    sysInitial();

    auto total_start = high_resolution_clock::now();

    double sum_reg = 0.0;
    for (int i = 0; i < 100; i++)
    {
        auto t1 = high_resolution_clock::now();
        Registration(password, identity);
        auto t2 = high_resolution_clock::now();
        sum_reg += duration<double, milli>(t2 - t1).count();
    }
    double avg_reg = sum_reg / 100.0;

    double sum_login = 0.0;
    for (int i = 0; i < 100; i++)
    {
        auto t1 = high_resolution_clock::now();
        Login(password, identity);
        auto t2 = high_resolution_clock::now();
        sum_login += duration<double, milli>(t2 - t1).count();
    }
    double avg_login = sum_login / 100.0;

    auto total_end = high_resolution_clock::now();
    double duration_total = duration<double, milli>(total_end - total_start).count() / 100.0;

    cout << "Registration Avg Time (100 runs): " << avg_reg << " ms" << endl;
    cout << "Login Avg Time (100 runs):        " << avg_login << " ms" << endl;
    cout << "Total execution time:              " << duration_total << " ms" << endl;

    pairing_clear(pairing);
    return 0;
}
