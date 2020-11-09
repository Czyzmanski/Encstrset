#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_set>
#include <unordered_map>

#include "encstrset.h"

#ifdef NDEBUG
static constexpr bool debug = false;
#else
static constexpr bool debug = true;
#endif

namespace {
    using std::endl;
    using std::string;
    using std::stringstream;

    using encrypted_t = std::unordered_map<unsigned long, std::unordered_set<string>>;

    using set_func_t = void (*)(unsigned long);
    using val_func_t = void (*)(unsigned long, const string &);

    std::ostream &cerr() {
        static std::ios_base::Init init;
        return std::cerr;
    }

    unsigned long &added_sets() {
        static unsigned long added_sets = 0;
        return added_sets;
    }

    encrypted_t &encrypted() {
        static encrypted_t encrypted;
        return encrypted;
    }

    inline void print_func_call_if_debug(const string &func_name,
                                         unsigned long id) {
        if (debug) {
            cerr() << func_name << "(" << id << ")" << endl;
        }
    }

    inline void print_func_call_if_debug(const string &func_name,
                                         unsigned long src_id,
                                         unsigned long dst_id) {
        if (debug) {
            cerr() << func_name << "(" << src_id << ", " << dst_id << ")" << endl;
        }
    }

    inline void print_func_call_if_debug(const string &func_name,
                                         unsigned long id,
                                         const string &value, const string &key) {
        if (debug) {
            cerr() << func_name << "(" << id << ", "
                   << value << ", " << key << ")" << endl;
        }
    }

    inline void print_set_info_if_debug(const string &func_name,
                                        unsigned long id, const string &info) {
        if (debug) {
            cerr() << func_name << ": " << "set #" << id << info << endl;
        }
    }

    inline void print_func_info_if_debug(const string &func_name,
                                         const string &info) {
        if (debug) {
            cerr() << func_name << info << endl;
        }
    }

    void clear_set(unsigned long id) {
        encrypted()[id].clear();
    }

    void erase_set(unsigned long id) {
        encrypted().erase(id);
    }

    void insert_value(unsigned long id, const string &value) {
        encrypted()[id].insert(value);
    }

    void erase_value(unsigned long id, const string &value) {
        encrypted()[id].erase(value);
    }

    inline bool is_set_present(const unsigned long id) {
        return encrypted().find(id) != encrypted().end();
    }

    inline bool is_value_present(const unsigned long id, const string &value) {
        return is_set_present(id) &&
               encrypted()[id].find(value) != encrypted()[id].end();
    }

    inline string string_repr(const char *str) {
        string enclosing = (str == nullptr ? "" : R"(")");
        return enclosing + (str == nullptr ? "NULL" : str) + enclosing;
    }

    string cypher(const string &s) {
        stringstream cyphered;
        cyphered << "cypher " << '"';

        size_t processed = 0;
        for (int c : s) {
            processed++;

            cyphered << std::uppercase << std::hex << c / 16 << c % 16;
            if (processed < s.length()) {
                cyphered << " ";
            }
        }

        cyphered << '"';
        return cyphered.str();
    }

    void encrypt(string &s, const string &key) {
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

    inline void rewrite(const char *src, string &dst) {
        if (src == nullptr) {
            dst = "";
        }
        else {
            dst = src;
        }
    }

    string rewrite_and_encrypt_value(const char *value, const char *key) {
        string new_value;
        rewrite(value, new_value);

        string new_key;
        rewrite(key, new_key);

        encrypt(new_value, new_key);
        return new_value;
    }

    void handle_set_operation(const string &func_name, unsigned long id,
                              const string &info_if_set_present,
                              const string &info_if_set_absent,
                              set_func_t func_if_set_present) {
        print_func_call_if_debug(func_name, id);

        if (is_set_present(id)) {
            func_if_set_present(id);
            print_set_info_if_debug(func_name, id, info_if_set_present);
        }
        else {
            print_set_info_if_debug(func_name, id, info_if_set_absent);
        }
    }

    bool handle_value_operation(const string &func_name, unsigned long id,
                                const char *value, const char *key,
                                const string &info_if_value_present,
                                const string &info_if_value_absent,
                                val_func_t func_if_value_present,
                                val_func_t func_if_value_absent,
                                bool res_if_value_present,
                                bool res_if_value_absent) {
        print_func_call_if_debug(func_name, id,
                                 string_repr(value), string_repr(key));

        if (value == nullptr) {
            print_func_info_if_debug(func_name, ": invalid value (NULL)");
            return false;
        }
        else if (!is_set_present(id)) {
            print_set_info_if_debug(func_name, id, " does not exist");
            return false;
        }
        else {
            string new_value = rewrite_and_encrypt_value(value, key);

            stringstream info;
            info << ", " << cypher(new_value);

            if (is_value_present(id, new_value)) {
                if (func_if_value_present != nullptr) {
                    func_if_value_present(id, new_value);
                }

                info << info_if_value_present;
                print_set_info_if_debug(func_name, id, info.str());

                return res_if_value_present;
            }
            else {
                if (func_if_value_absent != nullptr) {
                    func_if_value_absent(id, new_value);
                }

                info << info_if_value_absent;
                print_set_info_if_debug(func_name, id, info.str());

                return res_if_value_absent;
            }
        }
    }

}

namespace jnp1 {
    unsigned long encstrset_new() {
        if (debug) {
            cerr() << "encstrset_new" << "()" << endl;
        }

        std::unordered_set<string> new_set;
        encrypted().insert(std::make_pair(added_sets(), new_set));

        print_set_info_if_debug("encstrset_new", added_sets(), " created");

        return added_sets()++;
    }

    void encstrset_delete(unsigned long id) {
        handle_set_operation("encstrset_delete", id,
                             " deleted", " does not exist", erase_set);
    }

    size_t encstrset_size(unsigned long id) {
        print_func_call_if_debug("encstrset_size", id);

        if (!is_set_present(id)) {
            print_set_info_if_debug("encstrset_size", id, " does not exist");
            return 0;
        }

        stringstream info;
        info << " contains " << encrypted()[id].size() << " element(s)";

        print_set_info_if_debug("encstrset_size", id, info.str());

        return encrypted()[id].size();
    }

    bool encstrset_insert(unsigned long id, const char *value, const char *key) {
        return handle_value_operation("encstrset_insert", id, value, key,
                                      " was already present", " inserted",
                                      nullptr, insert_value, false, true);
    }

    bool encstrset_remove(unsigned long id, const char *value, const char *key) {
        return handle_value_operation("encstrset_remove", id, value, key,
                                      " removed", " was not present",
                                      erase_value, nullptr, true, false);
    }

    bool encstrset_test(unsigned long id, const char *value, const char *key) {
        return handle_value_operation("encstrset_test", id, value, key,
                                      " is present", " is not present",
                                      nullptr, nullptr, true, false);
    }

    void encstrset_clear(unsigned long id) {
        handle_set_operation("encstrset_clear", id,
                             " cleared", " does not exist", clear_set);
    }

    void encstrset_copy(unsigned long src_id, unsigned long dst_id) {
        print_func_call_if_debug("encstrset_copy", src_id, dst_id);

        if (!is_set_present(src_id)) {
            print_set_info_if_debug("encstrset_copy", src_id, " does not exist");
        }
        else if (!is_set_present(dst_id)) {
            print_set_info_if_debug("encstrset_copy", dst_id, " does not exist");
        }
        else {
            for (const string &s : encrypted()[src_id]) {
                bool added = encrypted()[dst_id].insert(s).second;

                stringstream info;
                info << ": ";

                if (added) {
                    info << cypher(s) << " copied from " << "set #"
                         << src_id << " to " << "set #" << dst_id;
                }
                else {
                    info << "copied " << cypher(s)
                         << " was already present in " << "set #" << dst_id;
                }

                print_func_info_if_debug("encstrset_copy", info.str());
            }
        }
    }
}
