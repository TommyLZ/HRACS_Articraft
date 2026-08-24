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

uint32_t pick_uint(const string &seed, uint64_t idx)
{
    string s = seed + "|IDX|" + to_string((long long)idx);
    auto h = sha256_bytes(sb(s));
    return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) | ((uint32_t)h[2] << 8) | (uint32_t)h[3];
}
int pick_index(const string &seed, uint64_t idx, int range)
{
    if (range <= 0)
        return 0;
    return (int)(pick_uint(seed, idx) % (uint32_t)range);
}

const int PASSPHRASE_WORDS_MIN = 3;
const int PASSPHRASE_WORDS_MAX = 6;
const vector<string> SEPARATORS = {" ", "-", "_", ""};

int pick_word_count(const string &seed, uint64_t idx)
{
    int range = PASSPHRASE_WORDS_MAX - PASSPHRASE_WORDS_MIN + 1;
    return PASSPHRASE_WORDS_MIN + pick_index(seed + "|WC", idx, range);
}

vector<string> load_wordlist(const string &path = "wordlist.txt")
{
    auto lines = read_lines_file(path, 2000000);
    if (!lines.empty())
        return lines;

    return {
        "correct", "horse", "battery", "staple", "purple", "monkey", "dishwasher",
        "orange", "tiger", "river", "mountain", "cloud", "silver", "forest", "winter",
        "summer", "guitar", "rocket", "pencil", "garden", "window", "coffee", "dragon",
        "castle", "shadow", "bridge", "island", "wizard", "planet", "engine", "hammer",
        "candle", "desert", "jungle", "meadow", "signal", "temple", "beacon", "anchor",
        "canyon", "cinder", "compass", "cricket", "falcon", "granite", "harbor", "ivory",
        "jasmine", "kernel", "lantern", "marble", "nebula", "opal", "pepper", "quartz",
        "raven", "sable", "thunder", "umbrella", "velvet", "walnut", "yonder", "zephyr",
        "amber", "basil", "cedar", "dune", "ember", "fable", "glacier", "harvest",
        "indigo", "jungle2", "kettle", "lagoon", "meridian", "nectar", "onyx", "prairie"};
}

string generate_passphrase(const vector<string> &wordlist, const string &seed, uint64_t idx)
{
    int wc = pick_word_count(seed, idx);
    vector<string> words;
    words.reserve(wc);
    for (int k = 0; k < wc; ++k)
    {
        int widx = pick_index(seed + "|W" + to_string(k), idx, (int)wordlist.size());
        string w = wordlist[widx];

        uint32_t r = pick_uint(seed + "|CASE" + to_string(k), idx);
        if (r % 3 == 0 && !w.empty())
            w[0] = toupper((unsigned char)w[0]);
        words.push_back(w);
    }
    int sep_idx = pick_index(seed + "|SEP", idx, (int)SEPARATORS.size());
    const string &sep = SEPARATORS[sep_idx];

    string phrase;
    for (size_t i = 0; i < words.size(); ++i)
    {
        if (i > 0)
            phrase += sep;
        phrase += words[i];
    }

    uint32_t suffix_roll = pick_uint(seed + "|SUFFIX", idx);
    if (suffix_roll % 2 == 0)
    {
        const string digits = "0123456789";
        const string symbols = "!@#$%^&*";
        phrase += digits[suffix_roll % digits.size()];
        if (suffix_roll % 4 == 0)
            phrase += symbols[(suffix_roll / 4) % symbols.size()];
    }
    return phrase;
}

void generate_mangled_passphrase_variants(const vector<string> &base_words, unordered_set<string> &outset, int &remaining)
{
    if (remaining <= 0 || base_words.empty())
        return;
    auto add_if_ok = [&](const string &s)
    {
        if (remaining <= 0 || s.empty())
            return;
        if (outset.insert(s).second)
            remaining--;
    };

    vector<string> suffixes = {"", "1", "123", "!", "2020", "2021", "99"};

    for (const auto &sep : SEPARATORS)
    {

        string joined_low;
        for (size_t i = 0; i < base_words.size(); ++i)
        {
            string w = base_words[i];
            transform(w.begin(), w.end(), w.begin(), [](unsigned char c)
                      { return tolower(c); });
            if (i > 0)
                joined_low += sep;
            joined_low += w;
        }

        string joined_title;
        for (size_t i = 0; i < base_words.size(); ++i)
        {
            string w = base_words[i];
            transform(w.begin(), w.end(), w.begin(), [](unsigned char c)
                      { return tolower(c); });
            if (!w.empty())
                w[0] = toupper((unsigned char)w[0]);
            if (i > 0)
                joined_title += sep;
            joined_title += w;
        }
        for (const auto &suf : suffixes)
        {
            add_if_ok(joined_low + suf);
            if (remaining <= 0)
                return;
            add_if_ok(joined_title + suf);
            if (remaining <= 0)
                return;
        }
    }
}

pair<vector<string>, vector<int>> make_candidate_passphrase_dict(
    int dictsize,
    const vector<string> &wordlist,
    const string &leak_file = "",
    const string &popular_file = "popular_passphrases.txt")
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
        ifstream ifs(leak_file);
        string line;
        while (getline(ifs, line) && remaining > 0)
        {
            size_t pos = line.find(':');
            if (pos == string::npos)
                continue;
            string pp = str_trim(line.substr(pos + 1));
            if (pp.empty())
                continue;
            if (seen.insert(pp).second)
            {
                out.push_back(pp);
                sources.push_back(0);
                remaining--;
            }
        }
    }

    auto popular = read_lines_file(popular_file, 10000);
    if (popular.empty())
        popular = {"correct horse battery staple", "iloveyou-forever", "letmein123!"};
    for (const auto &pp : popular)
    {
        if (remaining <= 0)
            break;
        if (seen.insert(pp).second)
        {
            out.push_back(pp);
            sources.push_back(1);
            remaining--;
        }
    }
    if (remaining <= 0)
        return {out, sources};

    unordered_set<string> variants;
    variants.reserve(remaining * 2);
    int rem_for_mangling = remaining;
    for (const auto &pp : popular)
    {
        if (rem_for_mangling <= 0)
            break;

        vector<string> words;
        string cur;
        for (char c : pp)
        {
            if (c == ' ' || c == '-' || c == '_')
            {
                if (!cur.empty())
                    words.push_back(cur);
                cur.clear();
            }
            else
                cur.push_back(c);
        }
        if (!cur.empty())
            words.push_back(cur);
        if (!words.empty())
            generate_mangled_passphrase_variants(words, variants, rem_for_mangling);
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
        string cand = generate_passphrase(wordlist, "DICT_FILL", seed_counter);
        if (seen.insert(cand).second)
        {
            out.push_back(cand);
            sources.push_back(3);
            remaining--;
        }
        seed_counter++;
        if (seed_counter > 20000000ULL)
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

        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (!line.empty())
        {
            out_pw.push_back(line);
            if ((int)out_pw.size() == M)
                break;
        }
    }
    return ((int)out_pw.size() == M);
}

void ensure_unique_passphrases(vector<string> &pw_vec, const string &uniq_seed = "UNIQUENESS")
{
    unordered_set<string> seen;
    seen.reserve(pw_vec.size() * 2);
    for (size_t i = 0; i < pw_vec.size(); ++i)
    {
        if (seen.insert(pw_vec[i]).second)
            continue;

        uint64_t trycnt = 1;
        string base = pw_vec[i];
        while (true)
        {
            string extra = to_string(pick_uint(uniq_seed + "|" + to_string((long long)i), trycnt) % 100000);
            string cand = base + "-" + extra;
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
        cerr << "Usage: ./scheme1_est_passphrase <pbc_param_file> [M] [dictsize] [time_per_match] [lock_seconds] [max_budget] [effective_cap]\n";
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

    auto wordlist = load_wordlist("wordlist.txt");
    cout << "# wordlist size = " << wordlist.size() << " (supply your own wordlist.txt for a realistic study)\n";

    auto dict_and_sources = make_candidate_passphrase_dict(dictsize, wordlist, "./leaked_creds.txt", "./popular_passphrases.txt");
    vector<string> dict = dict_and_sources.first;
    if ((int)dict.size() < dictsize)
    {
        uint64_t sc = 0;
        while ((int)dict.size() < dictsize)
        {
            string cand = generate_passphrase(wordlist, "DICT_FILL_EXT", sc++);
            dict.push_back(cand);
        }
    }

    cout << "# scheme1_pbc_incremental: param=" << param_file << ", M=" << M << ", dictsize=" << dictsize
         << ", mode=baseline (passphrase, " << PASSPHRASE_WORDS_MIN << "-" << PASSPHRASE_WORDS_MAX << " words)\n";
    cout << "budget,new_cracked,cumulative_success_rate,avg_guesses_per_cracked\n";

    vector<string> true_pw(M);
    string true_pw_file = "true_passphrase_" + to_string(M) + ".txt";
    bool read_ok = read_true_pw_file(true_pw_file, M, true_pw);
    if (!read_ok)
    {
        const double bias_gamma = 6.0;
        int TRUE_COUNT = M;
        for (int i = 0; i < M; ++i)
        {
            if (!dict.empty() && i < TRUE_COUNT)
            {
                string s = string("TRUEPP_FROM_DICT|") + to_string((long long)i);
                auto hv = sha256_bytes(vector<unsigned char>(s.begin(), s.end()));
                uint64_t v = 0;
                for (int b = 0; b < 8; ++b)
                    v = (v << 8) | (uint64_t)hv[b];
                double u = (double)v / (double)numeric_limits<uint64_t>::max();
                double biased = pow(u, bias_gamma);
                size_t idx = (size_t)floor(biased * (double)dict.size());
                if (idx >= dict.size())
                    idx = dict.size() - 1;
                true_pw[i] = dict[idx];
            }
            else
            {
                true_pw[i] = generate_passphrase(wordlist, "FALLBACKPP", (uint64_t)i + 9999ULL);
            }
        }
        ensure_unique_passphrases(true_pw, "UNIQ_TRUEPP_V1");
        if (!write_true_pw_file(true_pw_file, true_pw))
            cerr << "Warning: failed to write true passphrase file: " << true_pw_file << "\n";
        else
            cout << "# true passphrases written to " << true_pw_file << "\n";
    }
    else
    {
        cout << "# loaded true passphrases from " << true_pw_file << "\n";
        ensure_unique_passphrases(true_pw, "UNIQ_TRUEPP_V1_LOADED");
    }

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
        ofstream ofs("baseline_crackedpp_at.txt", ios::out | ios::trunc);
        for (int i = 0; i < M; ++i)
            ofs << cracked_at_attempt[i] << '\n';
    }
    cout << "# baseline per-user cracked attempts written to baseline_crackedpp_at.txt\n";

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
        ofstream ofs("rate_limited_estimated_crackedpp_at.txt", ios::out | ios::trunc);
        for (int i = 0; i < M; ++i)
            ofs << effective_attempt[i] << '\n';
    }
    cout << "# estimated rate-limited per-user attempts written to rate_limited_estimated_crackedpp_at.txt\n";

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
    cout << "#  - baseline_crackedpp_at.txt (per-user, M lines)\n";
    cout << "#  - baseline_curve.csv\n";
    cout << "#  - rate_limited_estimated_crackedpp_at.txt (per-user estimated, M lines, -1 = not within cap)\n";
    cout << "#  - rate_limited_estimated_curve.csv\n";

    return 0;
}