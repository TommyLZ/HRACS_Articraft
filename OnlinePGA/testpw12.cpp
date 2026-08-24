#include <bits/stdc++.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <sys/stat.h>
using namespace std;

bool file_exists(const string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}
static inline string str_trim(const string &s)
{
    size_t a = 0;
    while (a < s.size() && isspace((unsigned char)s[a]))
        a++;
    size_t b = s.size();
    while (b > a && isspace((unsigned char)s[b - 1]))
        b--;
    return s.substr(a, b - a);
}
vector<string> read_lines_file(const string &path, int max_lines = 1000000)
{
    vector<string> out;
    if (!file_exists(path))
        return out;
    ifstream ifs(path);
    if (!ifs)
        return out;
    string line;
    while (getline(ifs, line) && (int)out.size() < max_lines)
    {
        line = str_trim(line);
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

vector<unsigned char> sha256_bytes(const vector<unsigned char> &data)
{
    vector<unsigned char> out(32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, out.data(), nullptr);
    EVP_MD_CTX_free(ctx);
    return out;
}
string hexstr(const vector<unsigned char> &v)
{
    static const char *hex = "0123456789abcdef";
    string s;
    s.reserve(v.size() * 2);
    for (unsigned char c : v)
    {
        s.push_back(hex[(c >> 4) & 0xF]);
        s.push_back(hex[c & 0xF]);
    }
    return s;
}
vector<unsigned char> trunc144(const vector<unsigned char> &v)
{
    if ((int)v.size() < 18)
        return v;
    return vector<unsigned char>(v.begin(), v.begin() + 18);
}
vector<unsigned char> sb(const string &s)
{
    return vector<unsigned char>(s.begin(), s.end());
}

string deterministic_rand_string(const string &seed, uint64_t counter, int length, const string &charset)
{
    string out;
    out.reserve(length);
    uint64_t c = counter;
    int charset_len = (int)charset.size();
    int produced = 0;
    while (produced < length)
    {

        vector<unsigned char> inp(seed.begin(), seed.end());
        for (int i = 0; i < 8; ++i)
            inp.push_back((unsigned char)((c >> (56 - 8 * i)) & 0xFF));
        auto h = sha256_bytes(inp);

        for (unsigned char b : h)
        {
            if (produced >= length)
                break;
            int idx = b % charset_len;
            out.push_back(charset[idx]);
            produced++;
        }
        c++;
    }
    return out;
}

const int PASSWORD_LEN = 12;
const string CHARSET_FULL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?";

string pad_or_truncate(const string &s, int len)
{
    if ((int)s.size() >= len)
        return s.substr(0, len);
    string r = s;

    string pad = deterministic_rand_string("PAD", (uint64_t)s.size(), len - (int)s.size(), CHARSET_FULL);
    r += pad;
    return r;
}

struct SyntheticUser
{
    string name;
    string birthday;
    string phone;
};

vector<SyntheticUser> generate_synthetic_users(int M)
{
    vector<string> name_pool = {
        "alex", "li", "ming", "anna", "john", "sara", "chen", "wei", "kate", "liang",
        "mike", "zhang", "lily", "tom", "david", "xing", "hao", "xia", "rui", "jia"};

    vector<SyntheticUser> users;
    users.reserve(M);

    for (int i = 0; i < M; ++i)
    {
        SyntheticUser u;
        u.name = name_pool[i % (int)name_pool.size()] + to_string((i % 97));
        int year = 1970 + (i * 37) % 35;
        int month = 1 + (i * 13) % 12;
        int day = 1 + (i * 29) % 28;
        char buf[16];
        snprintf(buf, sizeof(buf), "%04d%02d%02d", year, month, day);
        u.birthday = string(buf);
        int prefix_case = i % 3;
        string prefix = (prefix_case == 0 ? "138" : (prefix_case == 1 ? "159" : "186"));
        long long tail = (1LL * i * 1315423911LL + 972663749) & 0xFFFFFFFFLL;
        char phonebuf[32];
        snprintf(phonebuf, sizeof(phonebuf), "%s%08lld", prefix.c_str(), (long long)(tail % 100000000LL));
        u.phone = string(phonebuf);
        users.push_back(u);
    }
    return users;
}

string generate_realistic_password_for_user(const SyntheticUser &u, uint64_t seed_idx)
{
    string n = u.name;
    string b = u.birthday;
    string p_tail = u.phone.substr(max(0, (int)u.phone.size() - 4));
    string seed = "REALPW_SEED_v1";
    string base = n + p_tail + b.substr(2, 4);
    base = pad_or_truncate(base, 8);
    string myseed = seed + "|" + u.name + "|" + u.birthday + "|" + u.phone;
    string tail = deterministic_rand_string(myseed, seed_idx, PASSWORD_LEN - (int)base.size(), CHARSET_FULL);
    string pw = base + tail;
    vector<unsigned char> h = sha256_bytes(vector<unsigned char>(myseed.begin(), myseed.end()));
    for (int t = 0; t < 3; ++t)
    {
        int pos = h[t] % PASSWORD_LEN;
        if (isalpha((unsigned char)pw[pos]))
        {
            if ((h[t + 3] & 1) == 0)
                pw[pos] = toupper((unsigned char)pw[pos]);
            else
                pw[pos] = tolower((unsigned char)pw[pos]);
        }
        else
        {
            const string symbols = "!@#$%^&*";
            pw[pos] = symbols[h[t + 4] % symbols.size()];
        }
    }
    return pad_or_truncate(pw, PASSWORD_LEN);
}

vector<string> load_popular_passwords(const string &path = "popular_passwords.txt", int max_lines = 10000)
{
    auto lines = read_lines_file(path, max_lines);
    if (!lines.empty())
        return lines;
    return {
        "123456", "password", "123456789", "qwerty", "abc123", "letmein", "dragon", "iloveyou", "111111", "baseball",
        "sunshine", "shadow", "master", "michael", "superman", "welcome", "password1", "admin", "login", "passw0rd"};
}
vector<string> load_leaked_passwords(const string &leak_file, int max_read = 1000000)
{
    vector<string> res;
    if (!file_exists(leak_file))
        return res;
    ifstream ifs(leak_file);
    if (!ifs)
        return res;
    string line;
    while (getline(ifs, line) && (int)res.size() < max_read)
    {
        if (line.empty())
            continue;
        size_t pos = line.find(':');
        if (pos == string::npos)
            continue;
        string pw = str_trim(line.substr(pos + 1));
        if (!pw.empty())
            res.push_back(pw);
    }
    return res;
}

vector<pair<char, char>> leet_subs = {
    {'a', '@'}, {'a', '4'}, {'o', '0'}, {'e', '3'}, {'i', '1'}, {'s', '$'}, {'l', '1'}, {'t', '7'}};
vector<string> keyboard_seqs = {"qwerty", "asdf", "zxcv", "qaz", "1qaz", "qwert", "qwe"};

void generate_mangled_variants_enhanced(const string &base, unordered_set<string> &outset, int &remaining)
{
    if (remaining <= 0)
        return;
    auto add_if_ok = [&](const string &s)
    {
        if (remaining <= 0)
            return;
        string t = s;
        if (t.empty())
            return;
        t = pad_or_truncate(t, PASSWORD_LEN);
        if (outset.insert(t).second)
            remaining--;
    };
    add_if_ok(base);
    if (remaining <= 0)
        return;
    string low = base, up = base;
    transform(low.begin(), low.end(), low.begin(), [](unsigned char c)
              { return tolower(c); });
    transform(up.begin(), up.end(), up.begin(), [](unsigned char c)
              { return toupper(c); });
    add_if_ok(low);
    add_if_ok(up);
    if (!base.empty())
    {
        string cap = base;
        cap[0] = toupper((unsigned char)cap[0]);
        add_if_ok(cap);
    }
    if (remaining <= 0)
        return;
    vector<string> suffixes = {"", "1", "12", "123", "!", "2020", "2021", "99", "!!", "@"};
    vector<string> prefixes = {"", "!", "@"};
    for (auto &suf : suffixes)
    {
        add_if_ok(base + suf);
        if (remaining <= 0)
            return;
    }
    for (auto &pre : prefixes)
    {
        add_if_ok(pre + base);
        if (remaining <= 0)
            return;
    }
    for (auto &seq : keyboard_seqs)
    {
        for (size_t pos = 0; pos <= base.size() && remaining > 0; ++pos)
        {
            add_if_ok(base.substr(0, pos) + seq + base.substr(pos));
            if (remaining <= 0)
                break;
        }
        if (remaining <= 0)
            break;
    }
    vector<int> pos_list;
    for (size_t i = 0; i < base.size(); ++i)
    {
        char c = tolower((unsigned char)base[i]);
        for (auto &p : leet_subs)
            if (p.first == c)
            {
                pos_list.push_back((int)i);
                break;
            }
    }
    for (int p : pos_list)
    {
        for (auto &s : leet_subs)
        {
            if (tolower(base[p]) == s.first)
                add_if_ok(base.substr(0, p) + s.second + base.substr(p + 1));
            if (remaining <= 0)
                return;
        }
    }
    for (size_t a = 0; a < pos_list.size() && remaining > 0; ++a)
        for (size_t b = a + 1; b < pos_list.size() && remaining > 0; ++b)
            for (auto &s1 : leet_subs)
                for (auto &s2 : leet_subs)
                    if (tolower(base[pos_list[a]]) == s1.first && tolower(base[pos_list[b]]) == s2.first)
                    {
                        string t = base;
                        t[pos_list[a]] = s1.second;
                        t[pos_list[b]] = s2.second;
                        add_if_ok(t);
                    }
}

pair<vector<string>, vector<int>> make_candidate_dict_pair(int dictsize, const string &leak_file = "", const string &popular_file = "popular_passwords.txt")
{
    vector<string> out;
    out.reserve(dictsize);
    vector<int> sources;
    sources.reserve(dictsize);
    unordered_set<string> seen;
    seen.reserve(dictsize * 2);
    int remaining = dictsize;

    if (!leak_file.empty() && file_exists(leak_file))
    {
        auto leaked = load_leaked_passwords(leak_file, dictsize);
        for (const auto &pw : leaked)
        {
            if (remaining <= 0)
                break;
            string p = pad_or_truncate(pw, PASSWORD_LEN);
            if (seen.insert(p).second)
            {
                out.push_back(p);
                sources.push_back(0);
                remaining--;
            }
        }
    }

    auto popular = load_popular_passwords(popular_file, 10000);
    for (const auto &pw : popular)
    {
        if (remaining <= 0)
            break;
        string p = pad_or_truncate(pw, PASSWORD_LEN);
        if (seen.insert(p).second)
        {
            out.push_back(p);
            sources.push_back(1);
            remaining--;
        }
    }
    if (remaining <= 0)
        return {out, sources};

    unordered_set<string> variants;
    variants.reserve(remaining * 2);
    int rem_for_mangling = remaining;
    for (const auto &pw : popular)
    {
        if (rem_for_mangling <= 0)
            break;
        generate_mangled_variants_enhanced(pw, variants, rem_for_mangling);
    }
    vector<string> variants_vec(variants.begin(), variants.end());
    sort(variants_vec.begin(), variants_vec.end());
    for (const auto &v : variants_vec)
    {
        if (remaining <= 0)
            break;
        if (seen.insert(v).second)
        {
            out.push_back(v);
            sources.push_back(2);
            remaining--;
        }
    }
    if (remaining <= 0)
        return {out, sources};

    uint64_t seed_counter = 12345;
    while (remaining > 0)
    {
        string cand = deterministic_rand_string("DICT_FILL", seed_counter, PASSWORD_LEN, CHARSET_FULL);
        if (seen.insert(cand).second)
        {
            out.push_back(cand);
            sources.push_back(3);
            remaining--;
        }
        seed_counter++;
        if (seed_counter > 10000000ULL)
            break;
    }

    return {out, sources};
}

vector<unsigned char> compute_rho_pbc(pairing_t &pairing, const string &ID, const string &pw, element_t &k_z)
{
    string idpw = ID + pw;
    element_t h1;
    element_init_G1(h1, pairing);
    element_from_hash(h1, (void *)idpw.data(), idpw.size());

    element_t h1_pow;
    element_init_G1(h1_pow, pairing);
    element_pow_zn(h1_pow, h1, k_z);

    int len = element_length_in_bytes(h1_pow);
    vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), h1_pow);

    vector<unsigned char> conc;
    conc.reserve(pw.size() + buf.size());
    conc.insert(conc.end(), pw.begin(), pw.end());
    conc.insert(conc.end(), buf.begin(), buf.end());
    auto H2 = sha256_bytes(conc);

    vector<unsigned char> conc2;
    conc2.reserve(ID.size() + H2.size());
    conc2.insert(conc2.end(), ID.begin(), ID.end());
    conc2.insert(conc2.end(), H2.begin(), H2.end());
    auto H3 = sha256_bytes(conc2);
    element_clear(h1);
    element_clear(h1_pow);

    return trunc144(H3);
}

bool write_true_pw_file(const string &path, const vector<string> &pw)
{
    cout << "write" << endl;
    ofstream ofs(path, ios::out | ios::trunc);
    if (!ofs)
        return false;
    for (const auto &s : pw)
        ofs << s << '\n';
    return true;
}
bool read_true_pw_file(const string &path, int M, vector<string> &out_pw)
{
    if (!file_exists(path))
        return false;
    ifstream ifs(path);
    if (!ifs)
        return false;
    out_pw.clear();
    out_pw.reserve(M);
    string line;
    while (getline(ifs, line))
    {
        if (!line.empty())
        {
            out_pw.push_back(pad_or_truncate(str_trim(line), PASSWORD_LEN));
            if ((int)out_pw.size() == M)
                break;
        }
    }
    return ((int)out_pw.size() == M);
}

void ensure_unique_passwords(vector<string> &pw_vec, const string &uniq_seed = "UNIQUENESS")
{
    unordered_set<string> seen;
    seen.reserve(pw_vec.size() * 2);
    cout << pw_vec.size() * 2 << endl;
    for (size_t i = 0; i < pw_vec.size(); ++i)
    {
        cout << "i=" << i << endl;
        if (pw_vec[i].empty())
            pw_vec[i] = pad_or_truncate("", PASSWORD_LEN);
        if (seen.insert(pw_vec[i]).second)
            continue;

        uint64_t trycnt = 1;
        string base = pw_vec[i];
        while (true)
        {
            string extra = deterministic_rand_string(uniq_seed + "|" + to_string((long long)i), trycnt, 6, CHARSET_FULL);
            string cand = base;
            int replace_len = min(6, PASSWORD_LEN);
            cand.replace(PASSWORD_LEN - replace_len, replace_len, extra.substr(0, replace_len));
            if (seen.insert(cand).second)
            {
                pw_vec[i] = cand;
                break;
            }
            trycnt++;
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        cerr << "Usage: ./scheme1_est12 <pbc_param_file> [M] [dictsize] [time_per_match] [lock_seconds] [max_budget] [effective_cap]\n";
        return 1;
    }
    string param_file = argv[1];
    int M = (argc > 2) ? stoi(argv[2]) : 20000;
    int dictsize = (argc > 3) ? stoi(argv[3]) : 1000000;
    double time_per_match = (argc > 4) ? atof(argv[4]) : 0.00325994;
    double lock_seconds = (argc > 5) ? atof(argv[5]) : 300.0;
    long long max_budget = (argc > 6) ? stoll(argv[6]) : 1000000LL;
    long long effective_cap = (argc > 7) ? stoll(argv[7]) : 1000000000000LL;

    long long lock_equiv = (long long)floor(lock_seconds / time_per_match + 0.5);

    string param;
    {
        ifstream ifs(param_file, ios::binary);
        if (!ifs)
        {
            cerr << "Failed to open param file: " << param_file << "\n";
            return 1;
        }
        stringstream ss;
        ss << ifs.rdbuf();
        param = ss.str();
    }
    pairing_t pairing;
    if (pairing_init_set_buf(pairing, param.c_str(), param.size()))
    {
        cerr << "pairing_init_set_buf failed\n";
        return 1;
    }

    element_t k_z;
    element_init_Zr(k_z, pairing);
    {
        const string seed = "fixed_k_for_testing_v1";
        auto seed_hash = sha256_bytes(vector<unsigned char>(seed.begin(), seed.end()));
        element_from_hash(k_z, seed_hash.data(), (int)seed_hash.size());
    }

    string targetID = "15926254568";

    auto dict_and_sources = make_candidate_dict_pair(dictsize, "./leaked_creds.txt", "./popular_passwords.txt");
    vector<string> dict = dict_and_sources.first;

    if ((int)dict.size() < dictsize)
    {
        uint64_t sc = 0;
        while ((int)dict.size() < dictsize)
        {
            string cand = deterministic_rand_string("DICT_FILL_EXT", sc++, PASSWORD_LEN, CHARSET_FULL);
            dict.push_back(cand);
        }
    }

    cout << "# scheme1_pbc_incremental: param=" << param_file << ", M=" << M << ", dictsize=" << dictsize << ", mode=baseline\n";
    cout << "budget,new_cracked,cumulative_success_rate,avg_guesses_per_cracked\n";

    auto users = generate_synthetic_users(M);
    vector<string> true_pw;
    true_pw.resize(M);
    string true_pw_file = "true_pw_M12_" + to_string(M) + ".txt";
    bool read_ok = read_true_pw_file(true_pw_file, M, true_pw);
    if (!read_ok)
    {

        const double bias_gamma = 6.0;
        int TRUE_COUNT = M;
        for (int i = 0; i < M; ++i)
        {
            if (!dict.empty() && i < TRUE_COUNT)
            {
                string s = string("TRUEPW_FROM_DICT|") + to_string((long long)i) + "|" + users[i].name + "|" + users[i].birthday;
                auto hv = sha256_bytes(vector<unsigned char>(s.begin(), s.end()));
                uint64_t v = 0;
                for (int b = 0; b < 8; ++b)
                    v = (v << 8) | (uint64_t)hv[b];
                double u = (double)v / (double)numeric_limits<uint64_t>::max();
                double biased = pow(u, bias_gamma);
                size_t idx = (size_t)floor(biased * (double)dict.size());
                if (idx >= dict.size())
                    idx = dict.size() - 1;
                true_pw[i] = pad_or_truncate(dict[idx], PASSWORD_LEN);
            }
            else
            {
                string seed = "FALLBACKPW|" + users[i].name + "|" + users[i].birthday + "|" + users[i].phone;
                true_pw[i] = deterministic_rand_string(seed, (uint64_t)i + 9999ULL, PASSWORD_LEN, CHARSET_FULL);
            }
        }
        cout << "ths" << endl;
        ensure_unique_passwords(true_pw, "UNIQ_TRUEPW_V1");
        cout << "hi" << endl;
        if (!write_true_pw_file(true_pw_file, true_pw))
        {
            cerr << "Warning: failed to write true password file: " << true_pw_file << "\n";
        }
        else
        {
            cout << "# true passwords written to " << true_pw_file << "\n";
        }
    }
    else
    {
        cout << "# loaded true passwords from " << true_pw_file << "\n";
        ensure_unique_passwords(true_pw, "UNIQ_TRUEPW_V1_LOADED");
    }

    cout << "hello" << endl;

    vector<vector<unsigned char>> rhos(M);
    vector<string> rhos_hex(M);
    for (int i = 0; i < M; ++i)
    {
        rhos[i] = compute_rho_pbc(pairing, targetID, true_pw[i], k_z);
        rhos_hex[i] = hexstr(rhos[i]);
    }

    vector<int> budgets;
    for (int i = 0;; ++i)
    {
        long long g = 1LL << (i + 1);
        if (g > dictsize)
        {
            budgets.push_back(dictsize);
            break;
        }
        budgets.push_back((int)g);
        if ((int)g == dictsize)
            break;
    }

    vector<vector<unsigned char>> dict_rhos(dictsize);
    unordered_map<string, int> rho_hex_to_min_index;
    rho_hex_to_min_index.reserve(dictsize * 2);

    vector<char> cracked(M, 0);
    int total_cracked = 0;
    long long cumulative_guesses_for_successes = 0;
    vector<int> cracked_at_attempt(M, -1);

    int prev_budget = 0;
    for (int budget : budgets)
    {
        int new_start = prev_budget;
        int new_end = min(budget, dictsize);
        int new_count = (new_start < new_end) ? (new_end - new_start) : 0;
        vector<string> new_hex(new_count);
        for (int jj = new_start; jj < new_end; ++jj)
        {
            auto rho = compute_rho_pbc(pairing, targetID, dict[jj], k_z);
            dict_rhos[jj] = rho;
            new_hex[jj - new_start] = hexstr(rho);
        }
        for (int jj = new_start; jj < new_end; ++jj)
        {
            const string &h = new_hex[jj - new_start];
            auto it = rho_hex_to_min_index.find(h);
            if (it == rho_hex_to_min_index.end())
                rho_hex_to_min_index.emplace(h, jj);
            else if (jj < it->second)
                it->second = jj;
        }

        int new_hits = 0;
        for (int i = 0; i < M; ++i)
        {
            if (cracked[i])
                continue;
            auto it = rho_hex_to_min_index.find(rhos_hex[i]);
            if (it != rho_hex_to_min_index.end())
            {
                int found_index = it->second;
                if (found_index <= new_end - 1)
                {
                    cracked[i] = 1;
                    total_cracked += 1;
                    new_hits += 1;
                    long long guesses_for_this_user = (long long)(found_index + 1);
                    cumulative_guesses_for_successes += guesses_for_this_user;
                    cracked_at_attempt[i] = (int)guesses_for_this_user;
                }
            }
        }
        double cumulative_success_rate = (double)total_cracked / (double)M;
        double avg_guesses_per_cracked = (total_cracked == 0) ? 0.0 : (double)cumulative_guesses_for_successes / (double)total_cracked;
        cout << budget << "," << new_hits << "," << cumulative_success_rate << "," << avg_guesses_per_cracked << "\n";
        if (total_cracked >= M)
            break;
        prev_budget = new_end;
    }

    {
        ofstream ofs("baseline_crackedpw12_at.txt", ios::out | ios::trunc);
        for (int i = 0; i < M; ++i)
            ofs << cracked_at_attempt[i] << '\n';
    }
    cout << "# baseline per-user cracked attempts written to baseline_cracked_at.txt\n";

    vector<long long> effective_attempt(M, -1);
    int rl_total_cracked = 0;
    long long rl_cumulative_effective = 0;
    for (int i = 0; i < M; ++i)
    {
        if (cracked_at_attempt[i] <= 0)
        {
            effective_attempt[i] = -1;
            continue;
        }
        long long base = cracked_at_attempt[i];
        long long extra = ((base - 1) / 5) * lock_equiv;
        long long eff = base + extra;
        if (eff <= effective_cap)
        {
            effective_attempt[i] = eff;
            rl_total_cracked += 1;
            rl_cumulative_effective += eff;
        }
        else
        {
            effective_attempt[i] = -1;
        }
    }

    {
        ofstream ofs("rate_limited_estimated_crackedpw12_at.txt", ios::out | ios::trunc);
        for (int i = 0; i < M; ++i)
            ofs << effective_attempt[i] << '\n';
    }
    cout << "# estimated rate-limited per-user attempts written to rate_limited_estimated_cracked_at.txt\n";

    cout << "# rate-limited estimated curve (lock_equiv_attempts=" << lock_equiv << ", effective_cap=" << effective_cap << ")\n";
    cout << "budget,new_cracked,cumulative_success_rate,avg_guesses_per_cracked\n";

    vector<long long> budgets_rl;
    for (int i = 0;; ++i)
    {
        long long g = 1LL << (i + 1);
        if (g > max_budget)
        {
            budgets_rl.push_back(max_budget);
            break;
        }
        budgets_rl.push_back(g);
        if (g >= max_budget)
            break;
        if (g > (1LL << 60))
            break;
    }
    if (effective_cap < max_budget)
        budgets_rl.push_back(effective_cap);

    vector<char> rl_counted(M, 0);
    rl_total_cracked = 0;
    rl_cumulative_effective = 0;
    for (auto budget : budgets_rl)
    {
        int new_hits = 0;
        for (int i = 0; i < M; ++i)
        {
            if (rl_counted[i])
                continue;
            if (effective_attempt[i] > 0 && effective_attempt[i] <= budget)
            {
                rl_counted[i] = 1;
                new_hits += 1;
                rl_total_cracked += 1;
                rl_cumulative_effective += effective_attempt[i];
            }
        }
        double cumulative_success_rate = (double)rl_total_cracked / (double)M;
        double avg_guesses_per_cracked = (rl_total_cracked == 0) ? 0.0 : (double)rl_cumulative_effective / (double)rl_total_cracked;
        cout << budget << "," << new_hits << "," << cumulative_success_rate << "," << avg_guesses_per_cracked << "\n";
        if (budget >= max_budget)
            break;
    }

    {
        ofstream ofs("baseline_curve.csv", ios::out | ios::trunc);
        ofs << "budget,new_cracked,cumulative_success_rate,avg_guesses_per_cracked\n";
        vector<char> counted(M, 0);
        int cum = 0;
        long long cumguess = 0;
        for (int budget : budgets)
        {
            int new_hits = 0;
            for (int i = 0; i < M; ++i)
            {
                if (counted[i])
                    continue;
                if (cracked_at_attempt[i] > 0 && cracked_at_attempt[i] <= budget)
                {
                    counted[i] = 1;
                    new_hits++;
                    cum++;
                    cumguess += cracked_at_attempt[i];
                }
            }
            double csr = (double)cum / (double)M;
            double avgg = (cum == 0) ? 0.0 : (double)cumguess / (double)cum;
            ofs << budget << "," << new_hits << "," << csr << "," << avgg << "\n";
        }
    }

    {
        ofstream ofs("rate_limited_estimated_curve.csv", ios::out | ios::trunc);
        ofs << "budget,new_cracked,cumulative_success_rate,avg_guesses_per_cracked\n";
        vector<char> counted(M, 0);
        int cum = 0;
        long long cumguess = 0;
        for (auto budget : budgets_rl)
        {
            int new_hits = 0;
            for (int i = 0; i < M; ++i)
            {
                if (counted[i])
                    continue;
                if (effective_attempt[i] > 0 && effective_attempt[i] <= budget)
                {
                    counted[i] = 1;
                    new_hits++;
                    cum++;
                    cumguess += effective_attempt[i];
                }
            }
            double csr = (double)cum / (double)M;
            double avgg = (cum == 0) ? 0.0 : (double)cumguess / (double)cum;
            ofs << budget << "," << new_hits << "," << csr << "," << avgg << "\n";
        }
    }

    element_clear(k_z);
    pairing_clear(pairing);

    cout << "# Done. Output files:\n";
    cout << "#  - baseline_cracked_at.txt (per-user, M lines)\n";
    cout << "#  - baseline_curve.csv\n";
    cout << "#  - rate_limited_estimated_cracked_at.txt (per-user estimated, M lines, -1 = not within cap)\n";
    cout << "#  - rate_limited_estimated_curve.csv\n";

    return 0;
}