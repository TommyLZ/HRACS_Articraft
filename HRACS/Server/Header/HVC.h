#pragma once

#include <pbc/pbc.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <libgen.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdint>
#include "PublicParam.h"

using namespace std;
namespace fs = filesystem;

void save_gen_to_file(const std::string &filename, element_t &key)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    int key_size = element_length_in_bytes(key);
    std::vector<unsigned char> buffer(key_size);
    element_to_bytes(buffer.data(), key);
    file.write(reinterpret_cast<const char *>(buffer.data()), key_size);
}

void load_gen_from_file(const std::string &filename, element_t &key)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    file.read(reinterpret_cast<char *>(buffer.data()), size);
    element_from_bytes(key, buffer.data());
}

inline void saveZToFile(const std::string &filename, element_t *z, int count)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open file for writing: " + filename);

    uint32_t cnt = static_cast<uint32_t>(count);
    file.write(reinterpret_cast<char *>(&cnt), sizeof(cnt));

    for (int i = 0; i < count; ++i)
    {
        size_t len = element_length_in_bytes(z[i]);
        uint32_t ulen = static_cast<uint32_t>(len);
        std::vector<unsigned char> buffer(len);
        element_to_bytes(buffer.data(), z[i]);

        file.write(reinterpret_cast<char *>(&ulen), sizeof(ulen));
        file.write(reinterpret_cast<char *>(buffer.data()), ulen);
    }
    file.close();
}

inline void loadZFromFile(const std::string &filename, element_t *z, int expected_count)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open file for reading: " + filename);

    uint32_t cnt = 0;
    file.read(reinterpret_cast<char *>(&cnt), sizeof(cnt));
    if ((int)cnt != expected_count)
        throw std::runtime_error("z_i count mismatch in file: " + filename);

    for (int i = 0; i < (int)cnt; ++i)
    {
        uint32_t ulen = 0;
        file.read(reinterpret_cast<char *>(&ulen), sizeof(ulen));
        if (!file)
            throw std::runtime_error("Failed to read length for z_i");

        std::vector<unsigned char> buffer(ulen);
        file.read(reinterpret_cast<char *>(buffer.data()), ulen);
        if ((uint32_t)file.gcount() != ulen)
            throw std::runtime_error("Failed to read z_i bytes");

        element_from_bytes(z[i], buffer.data());
    }
    file.close();
}

inline void saveG1ArrayToFile(const std::string &filename, element_t *arr, int count)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open G1 array file for writing: " + filename);

    uint32_t cnt = static_cast<uint32_t>(count);
    file.write(reinterpret_cast<char *>(&cnt), sizeof(cnt));

    for (int i = 0; i < count; ++i)
    {
        size_t len = element_length_in_bytes(arr[i]);
        uint32_t ulen = static_cast<uint32_t>(len);
        std::vector<unsigned char> buffer(len);
        element_to_bytes(buffer.data(), arr[i]);

        file.write(reinterpret_cast<char *>(&ulen), sizeof(ulen));
        file.write(reinterpret_cast<char *>(buffer.data()), ulen);
    }
    file.close();
}

inline void loadG1ArrayFromFile(const std::string &filename, element_t *arr, int expected_count)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Failed to open G1 array file for reading: " + filename);

    uint32_t cnt = 0;
    file.read(reinterpret_cast<char *>(&cnt), sizeof(cnt));
    if ((int)cnt != expected_count)
        throw std::runtime_error("G1 element count mismatch in file: " + filename);

    for (int j = 0; j < (int)cnt; ++j)
    {
        uint32_t ulen = 0;
        file.read(reinterpret_cast<char *>(&ulen), sizeof(ulen));
        if (!file)
            throw std::runtime_error("Failed to read G1 element length");

        std::vector<unsigned char> buffer(ulen);
        file.read(reinterpret_cast<char *>(buffer.data()), ulen);
        if ((uint32_t)file.gcount() != ulen)
            throw std::runtime_error("Failed to read G1 element bytes");

        element_from_bytes(arr[j], buffer.data());
    }
    file.close();
}

inline std::string h_i_path(const std::string &dir, int i)
{
    std::ostringstream oss;
    oss << dir << "/h_" << i << ".dat";
    return oss.str();
}

inline std::string h_ij_path(const std::string &dir, int i)
{
    std::ostringstream oss;
    oss << dir << "/hij_" << i << ".dat";
    return oss.str();
}

inline void set_deterministic_z(element_t &out, int size, int index)
{
    std::string label = "HRACS-HVC-z:" + std::to_string(size) + ":" + std::to_string(index);
    element_from_hash(out, (void *)label.data(), label.size());
}

class HVC
{
private:
    pairing_t &pairing;
    element_t *z;
    element_t *h;
    element_t **h_ij;
    element_t g;
    int size;

    string g_file_path = "../Key/g.dat";
    string z_file = "../Key/z_i.dat";
    string param_file = "../Param/a.param";
    string H_i_dir = "../Key/H_i";
    string H_ij_dir = "../Key/H";

public:
    HVC(int n, pairing_t &p) : size(n), pairing(p)
    {

        element_init_G1(g, pairing);

        std::string hvc_dir = "../Key/HVC_" + std::to_string(size);
        z_file = hvc_dir + "/z_i.dat";
        H_i_dir = hvc_dir + "/H_i";
        H_ij_dir = hvc_dir + "/H";

        if (fs::exists(g_file_path))
            load_gen_from_file(g_file_path, g);
        else
        {
            element_random(g);
            save_gen_to_file(g_file_path, g);
        }

        z = new element_t[size];
        h = new element_t[size];
        h_ij = new element_t *[size];
        for (int i = 0; i < size; ++i)
        {
            element_init_Zr(z[i], pairing);
            element_init_G1(h[i], pairing);
            h_ij[i] = nullptr;
        }

        if (!fs::exists(H_i_dir))
            fs::create_directories(H_i_dir);
        if (!fs::exists(H_ij_dir))
            fs::create_directories(H_ij_dir);

        bool z_loaded = false;
        if (fs::exists(z_file))
        {
            try
            {
                loadZFromFile(z_file, z, size);
                z_loaded = true;
                cout << "✅ Loaded z_i from file." << endl;
            }
            catch (const std::exception &e)
            {
                cout << "⚠️ Failed to load z_i: " << e.what() << endl;
            }
        }

        if (!z_loaded)
        {
            for (int i = 0; i < size; ++i)
                set_deterministic_z(z[i], size, i);
            saveZToFile(z_file, z, size);
            cout << "Saved new z_i to file." << endl;
        }

        for (int i = 0; i < size; ++i)
        {
            std::string hi_path = h_i_path(H_i_dir, i);

            if (fs::exists(hi_path))
            {
                try
                {
                    loadG1ArrayFromFile(hi_path, &h[i], 1);
                    continue;
                }
                catch (const std::exception &e)
                {
                    cout << "⚠️ Failed to load h_i[" << i << "]: " << e.what() << ". Recomputing." << endl;
                }
            }

            element_pow_zn(h[i], g, z[i]);

            saveG1ArrayToFile(hi_path, &h[i], 1);
        }

        for (int i = 0; i < size; ++i)
        {
            std::string path = h_ij_path(H_ij_dir, i);
            h_ij[i] = new element_t[size];
            for (int j = 0; j < size; ++j)
                element_init_G1(h_ij[i][j], pairing);

            if (fs::exists(path))
            {
                try
                {
                    loadG1ArrayFromFile(path, h_ij[i], size);
                    continue;
                }
                catch (const std::exception &e)
                {
                    cout << "⚠️ Failed to load h_[" << i << "]: " << e.what() << ". Recomputing." << endl;
                }
            }

            for (int j = 0; j < size; ++j)
            {
                element_t tmp;
                element_init_Zr(tmp, pairing);
                element_mul(tmp, z[i], z[j]);
                element_pow_zn(h_ij[i][j], g, tmp);
                element_clear(tmp);
            }
            saveG1ArrayToFile(path, h_ij[i], size);
        }

        cout << "✅ HVC setup completed. All h_i and h_ij are loaded/generated." << endl;
    }

    ~HVC()
    {
        element_clear(g);
        for (int i = 0; i < size; ++i)
        {
            element_clear(z[i]);
            element_clear(h[i]);
            for (int j = 0; j < size; ++j)
                element_clear(h_ij[i][j]);
            delete[] h_ij[i];
        }
        delete[] z;
        delete[] h;
        delete[] h_ij;
    }

    pairing_t &GetPairing() { return pairing; }

    void commit(element_t *m, int n, element_t &C, element_t &r)
    {

        element_random(r);
        element_set1(C);

        for (int i = 0; i < n; ++i)
        {

            element_t tmp;
            element_init_G1(tmp, pairing);

            element_pow_zn(tmp, h[i], m[i]);
            element_mul(C, C, tmp);
            element_clear(tmp);
        }

        element_t h_r;
        element_init_G1(h_r, pairing);
        element_pow_zn(h_r, h[n - 1], r);
        element_mul(C, C, h_r);
        element_clear(h_r);
    }

    void open(element_t *m, int n, int i, element_t &r, element_t &Lambda_i)
    {

        element_init_G1(Lambda_i, pairing);
        element_set1(Lambda_i);

        for (int j = 0; j < n; ++j)
        {
            if (j == i)
                continue;
            element_t tmp;
            element_init_G1(tmp, pairing);
            element_pow_zn(tmp, h_ij[i][j], m[j]);
            element_mul(Lambda_i, Lambda_i, tmp);
            element_clear(tmp);
        }

        element_t h_in_plus1;
        element_init_G1(h_in_plus1, pairing);
        element_pow_zn(h_in_plus1, h_ij[i][n - 1], r);
        element_mul(Lambda_i, Lambda_i, h_in_plus1);
        element_clear(h_in_plus1);
    }

    bool verify(element_t &C, element_t &m_i, element_t &Lambda_i, int i)
    {
        element_t left, right, tmp;
        element_init_GT(left, pairing);
        element_init_GT(right, pairing);
        element_init_G1(tmp, pairing);

        element_pow_zn(tmp, h[i], m_i);
        element_div(tmp, C, tmp);
        pairing_apply(left, tmp, h[i], pairing);
        pairing_apply(right, Lambda_i, g, pairing);

        bool result = !element_cmp(left, right);

        element_clear(left);
        element_clear(right);
        element_clear(tmp);

        return result;
    }

    bool verifyAggregate(element_t &C, const std::vector<int> &indices,
                         std::vector<element_t> &messages,
                         element_t &Lambda_agg)
    {
        if (indices.size() != messages.size())
            throw std::runtime_error("verifyAggregate: indices/messages size mismatch");

        element_t left_product, right, tmp_g1, tmp_gt;
        element_init_GT(left_product, pairing);
        element_init_GT(right, pairing);
        element_init_G1(tmp_g1, pairing);
        element_init_GT(tmp_gt, pairing);
        element_set1(left_product);

        for (size_t k = 0; k < indices.size(); ++k)
        {
            int i = indices[k];
            if (i < 0 || i >= size)
                throw std::runtime_error("verifyAggregate: index out of range");

            element_pow_zn(tmp_g1, h[i], messages[k]);
            element_div(tmp_g1, C, tmp_g1);
            pairing_apply(tmp_gt, tmp_g1, h[i], pairing);
            element_mul(left_product, left_product, tmp_gt);
        }

        pairing_apply(right, Lambda_agg, g, pairing);
        bool result = !element_cmp(left_product, right);

        element_clear(left_product);
        element_clear(right);
        element_clear(tmp_g1);
        element_clear(tmp_gt);

        return result;
    }

    void comHom(element_t &C1, element_t &C2, element_t &C_out)
    {
        element_init_G1(C_out, pairing);
        element_mul(C_out, C1, C2);
    }

    void openHom(element_t &Lambda_j1, element_t &Lambda_j2, element_t &Lambda_j_out)
    {
        element_init_G1(Lambda_j_out, pairing);
        element_mul(Lambda_j_out, Lambda_j1, Lambda_j2);
    }
};
