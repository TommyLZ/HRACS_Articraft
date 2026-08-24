#include <bits/stdc++.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <sys/stat.h>
using namespace std;

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
    return vector<unsigned char>(v.begin(), v.begin() + 18);
}
vector<unsigned char> sb(const string &s) { return vector<unsigned char>(s.begin(), s.end()); }
string fmt6(int x)
{
    char buf[8];
    snprintf(buf, sizeof(buf), "%06d", x % 1000000);
    return string(buf);
}
bool file_exists(const string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

vector<string> make_candidate_dict(int dictsize)
{
    vector<string> dict;
    dict.reserve(dictsize);
    int max_space = 1000000;
    for (int i = 0; i < dictsize; ++i)
        dict.push_back(fmt6(i % max_space));
    return dict;
}
vector<string> generate_true_pw_deterministic(int M)
{
    vector<string> res;
    res.reserve(M);
    const int MOD = 1000000;
    for (int i = 0; i < M; ++i)
    {
        long long val = (1LL * i * 37 + 13) % MOD;
        res.push_back(fmt6((int)val));
    }
    return res;
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
            if ((int)line.size() >= 6)
                out_pw.push_back(line.substr(0, 6));
            else
                out_pw.push_back(fmt6(0));
            if ((int)out_pw.size() == M)
                break;
        }
    }
    return ((int)out_pw.size() == M);
}
bool write_true_pw_file(const string &path, const vector<string> &pw)
{
    ofstream ofs(path, ios::out | ios::trunc);
    if (!ofs)
        return false;
    for (auto &s : pw)
        ofs << s << '\n';
    return true;
}

vector<unsigned char> compute_rho_pbc(pairing_t &pairing,
                                      const string &ID,
                                      const string &pw,
                                      element_t &k_z)
{
    element_t h1;
    element_init_G1(h1, pairing);
    string idpw = ID + pw;
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

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        cerr << "Usage: ./scheme1_est <pbc_param_file> [M] [dictsize] [time_per_match] [lock_seconds] [max_budget] [effective_cap]\n";
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
        element_from_hash(k_z, seed_hash.data(), 20);
    }

    string targetID = "15926254568";

    string true_pw_file = "true_pw_M6_" + to_string(M) + ".txt";
    vector<string> true_pw;
    bool read_ok = read_true_pw_file(true_pw_file, M, true_pw);
    if (!read_ok)
    {
        cout << "# true password file not found or incomplete (" << true_pw_file << "), generating deterministically and saving.\n";
        true_pw = generate_true_pw_deterministic(M);
        if (!write_true_pw_file(true_pw_file, true_pw))
            cerr << "Warning: failed to write true password file: " << true_pw_file << "\n";
        else
            cout << "# true passwords written to " << true_pw_file << "\n";
    }
    else
    {
        cout << "# loaded true passwords from " << true_pw_file << "\n";
    }

    vector<vector<unsigned char>> rhos(M);
    vector<string> rhos_hex(M);
    for (int i = 0; i < M; ++i)
    {
        rhos[i] = compute_rho_pbc(pairing, targetID, true_pw[i], k_z);
        rhos_hex[i] = hexstr(rhos[i]);
    }

    vector<string> dict = make_candidate_dict(dictsize);

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

    cout << "# scheme1_pbc_incremental: param=" << param_file << ", M=" << M << ", dictsize=" << dictsize << ", mode=baseline\n";
    cout << "budget,new_cracked,cumulative_success_rate,avg_guesses_per_cracked\n";

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
        ofstream ofs("baseline_crackedpw6_at.txt", ios::out | ios::trunc);
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
        ofstream ofs("rate_limited_estimated_crackedpw6_at.txt", ios::out | ios::trunc);
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
        int prev = 0;
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
