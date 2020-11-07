/*TODO: 
 * zmiania using namespace i bibliotek
 * najebanie komów
 */

#include <cassert>
#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_set>
#include <unordered_map>

using std::cerr;
using std::endl;
using std::setfill;
using std::setw;
using std::hex;
using std::string;
using std::stringstream;
using std::get;
using std::pair;
using std::make_pair;
using std::unordered_set;
using std::unordered_map;

static unsigned long added_sets = 0;
static unordered_map<unsigned long, unordered_set<string>> encrypted;

#ifdef NDEBUG
static const bool debug = false;
#else
static const bool debug = true;
#endif

static inline void print_func_call_if_debug(const string &func_name) {
    if (debug) {
        cerr << func_name << "()" << endl;
    }
}

static inline void print_func_call_if_debug(const string &func_name,
                                            unsigned long id) {
    if (debug) {
        cerr << func_name << "(" << id << ")" << endl;
    }
}

static inline void print_func_call_if_debug(const string &func_name,
                                            unsigned long src_id,
                                            unsigned long dst_id) {
    if (debug) {
        cerr << func_name << "(" << src_id << ", " << dst_id << ")" << endl;
    }
}

static inline void print_func_call_if_debug(const string &func_name,
                                            unsigned long id,
                                            const string &value, const string &key) {
    if (debug) {
        cerr << func_name << "(" << id << ", " << value << ", " << key << ")" << endl;
    }
}

static inline void print_set_info_if_debug(const string &func_name,
                                           unsigned long id, const string &info) {
    if (debug) {
        cerr << func_name << ": " << "set #" << id << info << endl;
    }
}

static inline void print_func_info_if_debug(const string &func_name,
                                            const string &info) {
    if (debug) {
        cerr << func_name << info << endl;
    }
}

static string string_repr(const char *str) {
    string enclosing = (str == nullptr ? "" : R"(")");
    return enclosing + (str == nullptr ? "NULL" : str) + enclosing;
}

static string cypher(const string &s) {
    stringstream cyphered;
    cyphered << "cypher ";
    cyphered << '"';

    size_t processed = 0;
    for (int c : s) {
        processed++;

        cyphered << setfill('0') << setw(2) << hex << c / 16 << c % 16;
        if (processed < s.length()) {
            cyphered << " ";
        }
    }

    cyphered << '"';
    return cyphered.str();
}

static bool is_set_present(const unsigned long id) {
    return encrypted.find(id) != encrypted.end();
}

static bool is_key_present(const unsigned long id, const string &s) {
    return is_set_present(id) && encrypted[id].find(s) != encrypted[id].end();
}

static void encrypt(string &s, const string &key) {
    if (!key.empty()) {
        string::const_iterator key_iter = key.begin();
        for (string::iterator iter = s.begin(); iter != s.end(); iter++) {
            *iter ^= *key_iter;
            key_iter++;
            if (key_iter == key.end()) {
                key_iter = key.begin();
            }
        }
    }
}

static void rewrite(const char *src, string &dst) {
    if (src == nullptr) {
        dst = "";
    }
    else {
        dst = src;
    }
}

static string rewrite_and_encrypt_value(const char *value, const char *key) {
    string new_value;
    rewrite(value, new_value);

    string new_key;
    rewrite(key, new_key);

    encrypt(new_value, new_key);
    return new_value;
}

unsigned long encstrset_new() {
    print_func_call_if_debug("encstrset_new");

    unordered_set<string> new_set;
    encrypted.insert(make_pair(added_sets, new_set));

    assert(is_set_present(added_sets));
    print_set_info_if_debug("encstrset_new", added_sets, " created");

    return added_sets++;
}

void encstrset_delete(unsigned long id) {
    print_func_call_if_debug("encstrset_delete", id);

    if (is_set_present(id)) {
        encrypted.erase(id);
        print_set_info_if_debug("encstrset_delete", id, " deleted");
    }
    else {
        print_set_info_if_debug("encstrset_delete", id, " does not exist");
    }

    assert(!is_set_present(id));
}

size_t encstrset_size(unsigned long id) {
    print_func_call_if_debug("encstrset_size", id);

    if (!is_set_present(id)) {
        print_set_info_if_debug("encstrset_size", id, " does not exist");
        return 0;
    }

    stringstream info;
    info << "contains " << encrypted[id].size() << " element(s)";
    print_set_info_if_debug("encstrset_size", id, info.str());

    return encrypted[id].size();
}

bool encstrset_insert(unsigned long id, const char *value, const char *key) {
    print_func_call_if_debug("encstrset_insert", id, string_repr(value),
                             string_repr(key));

    if (value == nullptr) {
        print_func_info_if_debug("encstrset_insert", ": invalid value (NULL)");
        return false;
    }
    else if (!is_set_present(id)) {
        print_set_info_if_debug("encstrset_insert", id, " does not exist");
        return false;
    }
    else {
        string new_value = rewrite_and_encrypt_value(value, key);
        stringstream info;
        info << ", " << cypher(new_value);

        if (is_key_present(id, new_value)) {
            info << " was already present";
            print_set_info_if_debug("encstrset_insert", id, info.str());
            return false;
        }
        else {
            encrypted[id].insert(new_value);
            info << " inserted";
            print_set_info_if_debug("encstrset_insert", id, info.str());
            return true;
        }
    }
}

bool encstrset_remove(unsigned long id, const char *value, const char *key) {
    print_func_call_if_debug("encstrset_remove", id, string_repr(value),
                             string_repr(key));

    if (value == nullptr) {
        print_func_info_if_debug("encstrset_remove", ": invalid value (NULL)");
        return false;
    }
    else if (!is_set_present(id)) {
        print_set_info_if_debug("encstrset_remove", id, " does not exist");
        return false;
    }
    else {
        string new_value = rewrite_and_encrypt_value(value, key);
        stringstream info;
        info << ", " << cypher(new_value);

        if (!is_key_present(id, new_value)) {
            info << " was not present";
            print_set_info_if_debug("encstrset_remove", id, info.str());
            return false;
        }
        else {
            encrypted[id].erase(new_value);
            info << " removed";
            print_set_info_if_debug("encstrset_remove", id, info.str());
            return true;
        }
    }
}

bool encstrset_test(unsigned long id, const char *value, const char *key) {
    print_func_call_if_debug("encstrset_test", id, string_repr(value),
                             string_repr(key));

    if (value == nullptr) {
        print_func_info_if_debug("encstrset_test", ": invalid value (NULL)");
        return false;
    }
    else if (!is_set_present(id)) {
        print_set_info_if_debug("encstrset_test", id, " does not exist");
        return false;
    }
    else {
        string new_value = rewrite_and_encrypt_value(value, key);
        stringstream info;
        info << ", " << cypher(new_value);

        if (!is_key_present(id, new_value)) {
            info << " is not present";
            print_set_info_if_debug("encstrset_test", id, info.str());
            return false;
        }
        else {
            info << " is present";
            print_set_info_if_debug("encstrset_test", id, info.str());
            return true;
        }
    }
}

void encstrset_clear(unsigned long id) {
    print_func_call_if_debug("encstrset_clear", id);

    if (!is_set_present(id)) {
        print_set_info_if_debug("encstrset_clear", id, " does not exist");
    }
    else {
        encrypted[id].clear();
        print_set_info_if_debug("encstrset_clear", id, " cleared");
    }
}

void encstrset_copy(unsigned long src_id, unsigned long dst_id) {
    print_func_call_if_debug("encstrset_copy", src_id, dst_id);

    if (!is_set_present(src_id)) {
        print_set_info_if_debug("encstrset_clear", src_id, " does not exist");
    }
    else if (!is_set_present(dst_id)) {
        print_set_info_if_debug("encstrset_clear", dst_id, " does not exist");
    }
    else {
        for (const string &s : encrypted[src_id]) {
            bool added = get<1>(encrypted[dst_id].insert(s));

            stringstream info;
            info << ": ";

            if (added) {
                info << cypher(s) << " copied from " << "set #" << src_id;
                info << " to " << "set #" << dst_id;
            }
            else {
                info << " copied " << cypher(s);
                info << " was already present in " << "set #" << dst_id;
            }

            print_func_info_if_debug("encstrset_clear", info.str());
        }
    }
}		
