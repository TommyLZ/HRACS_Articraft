#pragma once

#include <pbc/pbc.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#if defined(__has_include)
#if __has_include(<filesystem>)
#include <filesystem>
#define HRACS_USE_STD_FILESYSTEM 1
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
#define HRACS_USE_STD_FILESYSTEM 0
#else
#error "No filesystem support available"
#endif
#else
#include <filesystem>
#define HRACS_USE_STD_FILESYSTEM 1
#endif

#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include "HVC.h"

using namespace std;
#if HRACS_USE_STD_FILESYSTEM
namespace fs = std::filesystem;
#else
namespace fs = std::experimental::filesystem;
#endif

pairing_t pairing;
element_t g, h;

static constexpr int KEY_LEN = 32;
static constexpr int IV_LEN = 12;
static constexpr int TAG_LEN = 16;
static constexpr int PBKDF2_ITER = 100000;

pairing_t &sysInitial()
{
    cout << "*********************************System Initialization********************************" << endl;
    const std::string param_file = "../Param/a.param";

    char param[1024];
    std::ifstream file(param_file, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open parameter file: " + param_file);
    }

    size_t count = file.readsome(param, sizeof(param));
    if (count == 0)
    {
        throw std::runtime_error("Failed to read parameter file: " + param_file);
    }

    pairing_init_set_buf(pairing, param, count);

    element_init_G1(g, pairing);
    const std::string g_file = "../Key/g.dat";
    if (fs::exists(g_file))
    {
        std::ifstream g_in(g_file, std::ios::binary);
        g_in.seekg(0, std::ios::end);
        size_t g_size = static_cast<size_t>(g_in.tellg());
        g_in.seekg(0, std::ios::beg);
        std::vector<unsigned char> g_buf(g_size);
        g_in.read(reinterpret_cast<char *>(g_buf.data()), g_size);
        element_from_bytes(g, g_buf.data());
        cout << "Loaded public generator g from " << g_file << endl;
    }
    else
    {
        element_random(g);
        std::ofstream g_out(g_file, std::ios::binary);
        int g_size = element_length_in_bytes(g);
        std::vector<unsigned char> g_buf(g_size);
        element_to_bytes(g_buf.data(), g);
        g_out.write(reinterpret_cast<const char *>(g_buf.data()), g_buf.size());
        cout << "Generated and saved public generator g to " << g_file << endl;
    }

    cout << "System initialization finished!" << endl;

    return pairing;
}

bool save_element_G1(const char *filename, element_t g1_elem)
{

    FILE *fp = fopen(filename, "w");
    if (!fp)
    {
        cerr << "Error: cannot open " << filename << " for writing" << endl;
        return false;
    }

    if (element_out_str(fp, 10, g1_elem) == -1)
    {
        cerr << "Error: failed to write G1 element to " << filename << endl;
        fclose(fp);
        return false;
    }

    fclose(fp);
    cout << "G1 element successfully saved to " << filename << endl;

    return true;
}

bool Load_element_G1(const string &path, element_t &e)
{

    element_init_G1(e, pairing);

    ifstream fin(path);
    if (!fin.is_open())
    {
        cerr << "Error: cannot open " << path << endl;
        return false;
    }

    string elem_str((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
    fin.close();

    elem_str.erase(0, elem_str.find_first_not_of(" \n\r\t"));
    elem_str.erase(elem_str.find_last_not_of(" \n\r\t") + 1);

    if (element_set_str(e, elem_str.c_str(), 10) == 0)
    {
        cerr << "Error: failed to parse G1 element from file." << endl;
        return false;
    }

    element_printf("Loaded G1 element: %B\n", e);
    return true;
}

bool Load_element_Zr(const string &path, element_t &e)
{

    element_init_Zr(e, pairing);

    ifstream fin(path);
    if (!fin.is_open())
    {
        cerr << "Error: cannot open " << path << endl;
        return false;
    }

    string k_str;
    fin >> k_str;
    fin.close();

    if (element_set_str(e, k_str.c_str(), 10) == 0)
    {
        cerr << "Error: failed to parse Zr element from file." << endl;
        return false;
    }

    element_printf("Loaded Zr element: %B\n", e);
    return true;
}

string Sign(const std::string &hash, element_t secret_key)
{
    element_t h, sig;
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);

    element_from_hash(h, (void *)hash.c_str(), hash.size());

    element_pow_zn(sig, h, secret_key);

    char buffer[1024];
    element_snprint(buffer, sizeof(buffer), sig);

    element_clear(h);
    element_clear(sig);
    return std::string(buffer);
}

bool Verify(const std::string &hash, const std::string &signature, element_t public_key)
{
    element_t h, sig, temp1, temp2;
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    element_from_hash(h, (void *)hash.c_str(), hash.size());
    if (element_set_str(sig, signature.c_str(), 10) == 0)
    {
        cerr << "Error: failed to parse signature." << endl;
        element_clear(h);
        element_clear(sig);
        element_clear(temp1);
        element_clear(temp2);
        return false;
    }

    element_printf("The public key is %B\n", public_key);
    cout << "The hash is " << hash << endl;
    cout << "The signature is " << signature << endl;
    element_printf("The generator is %B\n", g);

    pairing_apply(temp1, sig, g, pairing);
    element_printf("The temp1 is %B\n", temp1);
    pairing_apply(temp2, h, public_key, pairing);
    element_printf("The temp2 is %B\n", temp2);

    bool result = (element_cmp(temp1, temp2) == 0);

    element_clear(h);
    element_clear(sig);
    element_clear(temp1);
    element_clear(temp2);

    return result;
}

bool save_string_to_file(const string &data, const string &path)
{
    ofstream fout(path, ios::binary);
    if (!fout.is_open())
    {
        cerr << "Error: cannot open " << path << " for writing." << endl;
        return false;
    }

    fout.write(data.data(), data.size());
    fout.close();

    cout << "String saved to " << path << endl;
    return true;
}

bool load_string_from_file(const string &path, string &data)
{
    ifstream fin(path, ios::binary);
    if (!fin.is_open())
    {
        cerr << "Error: cannot open " << path << " for reading." << endl;
        return false;
    }

    fin.seekg(0, ios::end);
    size_t size = fin.tellg();
    fin.seekg(0, ios::beg);

    data.resize(size);
    fin.read(&data[0], size);
    fin.close();

    cout << "String loaded from " << path << endl;
    return true;
}

std::string to_hex(const std::vector<unsigned char> &v)
{
    std::ostringstream oss;
    for (unsigned char c : v)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}

void handle_openssl_errors()
{
    ERR_print_errors_fp(stderr);
}

bool read_file_all(const fs::path &p, std::vector<unsigned char> &out)
{
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs)
        return false;

    ifs.seekg(0, std::ios::end);
    auto size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    if (size <= 0)
    {
        out.clear();
        return true;
    }
    out.resize((size_t)size);
    ifs.read((char *)out.data(), size);
    return !!ifs;
}

bool write_file_all(const fs::path &p, const std::vector<unsigned char> &data)
{
    std::ofstream ofs(p, std::ios::binary);
    if (!ofs)
        return false;
    ofs.write((const char *)data.data(), data.size());
    return !!ofs;
}

bool aes_gcm_encrypt(const std::vector<unsigned char> &plaintext,
                     const std::vector<unsigned char> &aad,
                     const std::vector<unsigned char> &key,
                     std::vector<unsigned char> &iv_out,
                     std::vector<unsigned char> &ciphertext_out,
                     std::vector<unsigned char> &tag_out)
{
    bool ok = false;
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0, outlen = 0;

    if (key.size() != KEY_LEN)
    {
        std::cerr << "Key length must be " << KEY_LEN << " bytes\n";
        return false;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handle_openssl_errors();
        return false;
    }

    iv_out.resize(IV_LEN);
    if (RAND_bytes(iv_out.data(), IV_LEN) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_out.data()) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }

    if (!aad.empty())
    {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1)
        {
            handle_openssl_errors();
            goto cleanup;
        }
    }

    ciphertext_out.resize(plaintext.size());
    if (!plaintext.empty())
    {
        if (EVP_EncryptUpdate(ctx, ciphertext_out.data(), &len, plaintext.data(), (int)plaintext.size()) != 1)
        {
            handle_openssl_errors();
            goto cleanup;
        }
        outlen = len;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext_out.data() + outlen, &len) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }
    outlen += len;
    ciphertext_out.resize(outlen);

    tag_out.resize(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag_out.data()) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }

    ok = true;

cleanup:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aes_gcm_decrypt(const std::vector<unsigned char> &ciphertext,
                     const std::vector<unsigned char> &aad,
                     const std::vector<unsigned char> &key,
                     const std::vector<unsigned char> &iv,
                     const std::vector<unsigned char> &tag,
                     std::vector<unsigned char> &plaintext_out)
{
    bool ok = false;
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0, outlen = 0;

    if (key.size() != KEY_LEN)
    {
        std::cerr << "Key length error\n";
        return false;
    }
    if (iv.size() != IV_LEN)
    {
        std::cerr << "IV length error\n";
        return false;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handle_openssl_errors();
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }

    if (!aad.empty())
    {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1)
        {
            handle_openssl_errors();
            goto cleanup;
        }
    }

    plaintext_out.resize(ciphertext.size());
    if (!ciphertext.empty())
    {
        if (EVP_DecryptUpdate(ctx, plaintext_out.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1)
        {
            handle_openssl_errors();
            goto cleanup;
        }
        outlen = len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void *)tag.data()) != 1)
    {
        handle_openssl_errors();
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext_out.data() + outlen, &len) != 1)
    {
        std::cerr << "Decryption failed: authentication tag mismatch\n";
        goto cleanup;
    }
    outlen += len;
    plaintext_out.resize(outlen);

    ok = true;
cleanup:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool encrypt_file_to_dirs(const fs::path &in_path, const fs::path &out_dir, const fs::path &tag_dir, const std::vector<unsigned char> &key)
{
    std::vector<unsigned char> plaintext;
    if (!read_file_all(in_path, plaintext))
    {
        std::cerr << "Failed to read " << in_path << "\n";
        return false;
    }

    std::string filename = in_path.filename().string();
    std::vector<unsigned char> aad(filename.begin(), filename.end());

    std::vector<unsigned char> iv, ciphertext, tag;
    if (!aes_gcm_encrypt(plaintext, aad, key, iv, ciphertext, tag))
    {
        std::cerr << "Encryption failed for " << in_path << "\n";
        return false;
    }

    std::vector<unsigned char> outbuf;
    outbuf.reserve(iv.size() + ciphertext.size());
    outbuf.insert(outbuf.end(), iv.begin(), iv.end());
    outbuf.insert(outbuf.end(), ciphertext.begin(), ciphertext.end());

    fs::create_directories(out_dir);
    fs::create_directories(tag_dir);

    fs::path out_file = out_dir / filename;
    fs::path tag_file = tag_dir / (filename + ".tag");

    if (!write_file_all(out_file, outbuf))
    {
        std::cerr << "Failed to write ciphertext " << out_file << "\n";
        return false;
    }
    if (!write_file_all(tag_file, tag))
    {
        std::cerr << "Failed to write tag " << tag_file << "\n";
        return false;
    }

    return true;
}

bool decrypt_file_from_dirs(const fs::path &cipher_path, const fs::path &tag_dir, const fs::path &out_dir, const std::vector<unsigned char> &key)
{
    std::vector<unsigned char> inbuf;
    if (!read_file_all(cipher_path, inbuf))
    {
        std::cerr << "Failed to read ciphertext " << cipher_path << "\n";
        return false;
    }
    if ((int)inbuf.size() < IV_LEN)
    {
        std::cerr << "Ciphertext too short: " << cipher_path << "\n";
        return false;
    }

    std::string filename = cipher_path.filename().string();
    fs::path tag_file = tag_dir / (filename + ".tag");

    std::vector<unsigned char> tag;
    if (!read_file_all(tag_file, tag))
    {
        std::cerr << "Failed to read tag " << tag_file << "\n";
        return false;
    }
    if ((int)tag.size() != TAG_LEN)
    {
        std::cerr << "Tag length incorrect for " << tag_file << "\n";
        return false;
    }

    std::vector<unsigned char> iv(inbuf.begin(), inbuf.begin() + IV_LEN);
    std::vector<unsigned char> ciphertext(inbuf.begin() + IV_LEN, inbuf.end());

    std::vector<unsigned char> aad(filename.begin(), filename.end());
    std::vector<unsigned char> plaintext;

    if (!aes_gcm_decrypt(ciphertext, aad, key, iv, tag, plaintext))
    {
        std::cerr << "Decryption/auth failed for " << cipher_path << "\n";
        return false;
    }

    fs::create_directories(out_dir);
    fs::path out_file = out_dir / filename;

    if (!write_file_all(out_file, plaintext))
    {
        std::cerr << "Failed to write decrypted file " << out_file << "\n";
        return false;
    }
    return true;
}

bool encrypt_folder(const fs::path &in_dir,
                    const fs::path &out_dir,
                    const fs::path &tag_dir,
                    const std::vector<unsigned char> &key,
                    size_t n)
{
    if (!fs::exists(in_dir) || !fs::is_directory(in_dir))
    {
        std::cerr << "Input directory invalid: " << in_dir << "\n";
        return false;
    }

    std::error_code ec;
    if (!fs::exists(out_dir))
    {
        fs::create_directories(out_dir, ec);
        if (ec)
        {
            std::cerr << "Failed to create out_dir: " << out_dir << " (" << ec.message() << ")\n";
            return false;
        }
    }
    if (!fs::exists(tag_dir))
    {
        fs::create_directories(tag_dir, ec);
        if (ec)
        {
            std::cerr << "Failed to create tag_dir: " << tag_dir << " (" << ec.message() << ")\n";
            return false;
        }
    }

    std::vector<fs::directory_entry> files;
    for (auto &entry : fs::directory_iterator(in_dir, ec))
    {
        if (ec)
        {
            std::cerr << "Directory iteration error: " << ec.message() << "\n";
            return false;
        }
        if (entry.is_regular_file())
            files.push_back(entry);
    }

    std::sort(files.begin(), files.end(), [](const fs::directory_entry &a, const fs::directory_entry &b)
              { return a.path().filename().string() < b.path().filename().string(); });

    size_t to_process = std::min(n, files.size());
    size_t processed = 0;
    for (size_t i = 0; i < to_process; ++i)
    {
        const fs::path file = files[i].path();
        if (!encrypt_file_to_dirs(file, out_dir, tag_dir, key))
        {
            std::cerr << "Failed to encrypt file: " << file << "\n";
            return false;
        }
        ++processed;
    }

    std::cout << "Encrypted " << processed << " file(s) from " << in_dir << " -> " << out_dir << "\n";
    return true;
}

bool decrypt_folder(const fs::path &cipher_dir,
                    const fs::path &tag_dir,
                    const fs::path &out_dir,
                    const std::vector<unsigned char> &key,
                    size_t n)
{
    if (!fs::exists(cipher_dir) || !fs::is_directory(cipher_dir))
    {
        std::cerr << "Cipher directory invalid: " << cipher_dir << "\n";
        return false;
    }

    std::error_code ec;
    if (!fs::exists(out_dir))
    {
        fs::create_directories(out_dir, ec);
        if (ec)
        {
            std::cerr << "Failed to create out_dir: " << out_dir << " (" << ec.message() << ")\n";
            return false;
        }
    }

    std::vector<fs::directory_entry> files;
    for (auto &entry : fs::directory_iterator(cipher_dir, ec))
    {
        if (ec)
        {
            std::cerr << "Directory iteration error: " << ec.message() << "\n";
            return false;
        }
        if (entry.is_regular_file())
            files.push_back(entry);
    }

    std::sort(files.begin(), files.end(), [](const fs::directory_entry &a, const fs::directory_entry &b)
              { return a.path().filename().string() < b.path().filename().string(); });

    size_t to_process = std::min(n, files.size());
    size_t processed = 0;
    for (size_t i = 0; i < to_process; ++i)
    {
        const fs::path cipher_file = files[i].path();
        if (!decrypt_file_from_dirs(cipher_file, tag_dir, out_dir, key))
        {
            std::cerr << "Failed to decrypt file: " << cipher_file << "\n";
            return false;
        }
        ++processed;
    }

    std::cout << "Decrypted " << processed << " file(s) from " << cipher_dir << " -> " << out_dir << "\n";
    return true;
}

bool read_file_to_string(const std::string &path, std::string &out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open())
        return false;
    out.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return true;
}

bool read_file_binary(const std::string &path, std::string &out)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return false;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    out = oss.str();
    return true;
}

bool save_element_G1_compressed(const std::string &path, element_t &e)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs)
        return false;
    int len = element_length_in_bytes_compressed(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes_compressed(buf.data(), e);
    ofs.write(reinterpret_cast<const char *>(buf.data()), len);
    return !!ofs;
}

bool save_element_Zr(const std::string &path, element_t &e)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs)
        return false;
    int len = element_length_in_bytes(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), e);
    ofs.write(reinterpret_cast<const char *>(buf.data()), len);
    return !!ofs;
}

bool load_element_G1_compressed(const std::string &path, element_t &e)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return false;
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (buf.empty())
        return false;
    element_from_bytes_compressed(e, buf.data());
    return true;
}

bool load_element_Zr(const std::string &path, element_t &e)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return false;
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (buf.empty())
        return false;
    element_from_bytes(e, buf.data());
    return true;
}
