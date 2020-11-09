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

    using set_func_t = void (*)(unsigned long);
    using val_func_t = void (*)(unsigned long, const string &);

    using encrypted_t = std::unordered_map<unsigned long, std::unordered_set<string>>;
    using msg_pair_t = std::pair<string, string>;
    using val_func_pair_t = std::pair<val_func_t, val_func_t>;
    using res_pair_t = std::pair<bool, bool>;

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

    inline string set_id_msg() {
        return "set #";
    }

    inline string set_not_present_msg() {
        return " does not exist";
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

    inline void print_set_msg_if_debug(const string &func_name,
                                       unsigned long id, const string &msg) {
        if (debug) {
            cerr() << func_name << ": " << set_id_msg() << id << msg << endl;
        }
    }

    inline void print_func_msg_if_debug(const string &func_name,
                                        const string &msg) {
        if (debug) {
            cerr() << func_name << msg << endl;
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

    string encrypt_value(const char *value, const char *key) {
        if (value == nullptr) {
            return "";
        }
        else if (key == nullptr) {
            return string(value);
        }
        else {
            string enc_value = value;
            const string key_str = key;

            if (!key_str.empty()) {
                string::iterator iter = enc_value.begin();
                string::const_iterator key_iter = key_str.begin();

                while (iter != enc_value.end()) {
                    *iter++ ^= *key_iter++;

                    if (key_iter == key_str.end()) {
                        key_iter = key_str.begin();
                    }
                }
            }

            return enc_value;
        }
    }

    void handle_set_operation(const string &func_name, unsigned long id,
                              const msg_pair_t &msg_pair,
                              set_func_t func_if_set_present) {
        print_func_call_if_debug(func_name, id);

        if (is_set_present(id)) {
            func_if_set_present(id);
            print_set_msg_if_debug(func_name, id, msg_pair.first);
        }
        else {
            print_set_msg_if_debug(func_name, id, msg_pair.second);
        }
    }

    bool handle_value_operation(const string &func_name, unsigned long id,
                                const char *value, const char *key,
                                const msg_pair_t &msg_pair,
                                const val_func_pair_t val_func_pair,
                                const res_pair_t res_pair) {
        print_func_call_if_debug(func_name, id,
                                 string_repr(value), string_repr(key));

        if (value == nullptr) {
            print_func_msg_if_debug(func_name, ": invalid value (NULL)");
            return false;
        }
        else if (!is_set_present(id)) {
            print_set_msg_if_debug(func_name, id, set_not_present_msg());
            return false;
        }
        else {
            string new_value = encrypt_value(value, key);

            stringstream msg;
            msg << ", " << cypher(new_value);

            if (is_value_present(id, new_value)) {
                if (val_func_pair.first != nullptr) {
                    val_func_pair.first(id, new_value);
                }

                msg << msg_pair.first;
                print_set_msg_if_debug(func_name, id, msg.str());

                return res_pair.first;
            }
            else {
                if (val_func_pair.second != nullptr) {
                    val_func_pair.second(id, new_value);
                }

                msg << msg_pair.second;
                print_set_msg_if_debug(func_name, id, msg.str());

                return res_pair.second;
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
        encrypted().insert({added_sets(), new_set});

        print_set_msg_if_debug("encstrset_new", added_sets(), " created");

        return added_sets()++;
    }

    void encstrset_delete(unsigned long id) {
        handle_set_operation("encstrset_delete", id,
                             {" deleted", set_not_present_msg()}, erase_set);
    }

    size_t encstrset_size(unsigned long id) {
        print_func_call_if_debug("encstrset_size", id);

        if (!is_set_present(id)) {
            print_set_msg_if_debug("encstrset_size", id, set_not_present_msg());
            return 0;
        }

        stringstream msg;
        msg << " contains " << encrypted()[id].size() << " element(s)";

        print_set_msg_if_debug("encstrset_size", id, msg.str());

        return encrypted()[id].size();
    }

    bool encstrset_insert(unsigned long id, const char *value, const char *key) {
        return handle_value_operation("encstrset_insert", id, value, key,
                                      {" was already present", " inserted"},
                                      {nullptr, insert_value}, {false, true});
    }

    bool encstrset_remove(unsigned long id, const char *value, const char *key) {
        return handle_value_operation("encstrset_remove", id, value, key,
                                      {" removed", " was not present"},
                                      {erase_value, nullptr}, {true, false});
    }

    bool encstrset_test(unsigned long id, const char *value, const char *key) {
        return handle_value_operation("encstrset_test", id, value, key,
                                      {" is present", " is not present"},
                                      {nullptr, nullptr}, {true, false});
    }

    void encstrset_clear(unsigned long id) {
        handle_set_operation("encstrset_clear", id,
                             {" cleared", set_not_present_msg()}, clear_set);
    }

    void encstrset_copy(unsigned long src_id, unsigned long dst_id) {
        print_func_call_if_debug("encstrset_copy", src_id, dst_id);

        if (!is_set_present(src_id)) {
            print_set_msg_if_debug("encstrset_copy", src_id, set_not_present_msg());
        }
        else if (!is_set_present(dst_id)) {
            print_set_msg_if_debug("encstrset_copy", dst_id, set_not_present_msg());
        }
        else {
            for (const string &s : encrypted()[src_id]) {
                bool added = encrypted()[dst_id].insert(s).second;

                stringstream msg;
                msg << ": ";

                if (added) {
                    msg << cypher(s) << " copied from " << set_id_msg()
                        << src_id << " to " << set_id_msg() << dst_id;
                }
                else {
                    msg << "copied " << cypher(s)
                        << " was already present in " << set_id_msg() << dst_id;
                }

                print_func_msg_if_debug("encstrset_copy", msg.str());
            }
        }
    }
}
