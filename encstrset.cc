/** @file
 * Implementation of: encstrset.
 *
 * @author Kamil Zwierzchowski 418510
 * @author Szymon Czyżmański 417797
 */

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

    /**
     * Funtion used to perform operation on set with given id.
     */
    using set_func_t = void (*)(unsigned long);
    /**
     * Function used to perform operation on passed encrypted value and set with
     * given id.
     */
    using val_func_t = void (*)(unsigned long, const string &);
    /**
     * Unordered set storing @p string objects representing encrypted values.
     */
    using enc_set_t = std::unordered_set<string>;
    /**
     * Unordered map storing @p enc_set_t objects by their ids.
     */
    using id_to_enc_set_t = std::unordered_map<unsigned long, enc_set_t>;
    /**
     * Pair storing @p string objects, representing diagnostic messages
     * printed if debug mode is on.
     */
    using msg_pair_t = std::pair<string, string>;
    /**
     * Pair storing @p val_func_t pointers to functions performing operations
     * on given value and specified set.
     */
    using val_func_pair_t = std::pair<val_func_t, val_func_t>;
    /**
     * Pair storing @p bool objects to be returned when handling value operation
     * with given set.
     */
    using res_pair_t = std::pair<bool, bool>;

    /** @brief Wrapper function of std::cerr.
     * Initialise standard stream objects and return reference to std::cerr.
     * Standard stream objects are only initialised at first invocation
     * of the function.
     * @return Reference to standard error stream @p std::cerr.
     */
    std::ostream &cerr() {
        static std::ios_base::Init init;
        return std::cerr;
    }

    /** @brief Wrapper function of the counter of sets added.
     * Initialise counter of added sets and return reference to it.
     * Counter is only initialised at first invocation of the function.
     * @return Reference to counter of added sets.
     */
    unsigned long &added_sets() {
        static unsigned long added_sets = 0;
        return added_sets;
    }

    /** @brief Wrapper function of map storing sets by their identifiers.
     * Initialise map storing sets by their identifiers and return reference to it.
     * Map is only initialised at first invocation of the function.
     * @return Reference to map storing sets by their identifiers.
     */
    id_to_enc_set_t &id_to_enc_set() {
        static id_to_enc_set_t id_to_enc_set;
        return id_to_enc_set;
    }

    /** @brief Wrapper function of string literal used to represent set
     * in diagnostic messages.
     * @return String literal used to represent set.
     */
    inline string set_id_msg() {
        return "set #";
    }

    /** @brief Wrapper function of string literal informing that set is not
     * present, used in diagnostic messages.
     * @return String literal used to inform that set is not present.
     */
    inline string set_not_present_msg() {
        return " does not exist";
    }

    /** @brief Print function call if debug mode is on.
     * @param func_name - name of the called function to print.
     * @param id - set identifier passed to function @p func_name.
     */
    inline void print_func_call_if_debug(const string &func_name,
                                         unsigned long id) {
        if (debug) {
            cerr() << func_name << "(" << id << ")" << endl;
        }
    }

    /** @brief Print function call if debug mode is on.
     * @param func_name - name of the called function to print.
     * @param src_id - set id passed to function @p func_name from where
     *                 encrypted values are copied.
     * @param dst_id - set id passed to fucntion @p func_name where encrypted
     *                 values are copied to.
     */
    inline void print_func_call_if_debug(const string &func_name,
                                         unsigned long src_id,
                                         unsigned long dst_id) {
        if (debug) {
            cerr() << func_name << "(" << src_id << ", " << dst_id << ")" << endl;
        }
    }

    /** @brief Print message when performing set operation.
     * @param func_name - name of the function where set operation is performed.
     * @param id - set identifier.
     * @param msg - message to print.
     */
    inline void print_set_msg_if_debug(const string &func_name,
                                       unsigned long id, const string &msg) {
        if (debug) {
            cerr() << func_name << ": " << set_id_msg() << id << msg << endl;
        }
    }

    /** @brief Print message when invoking function.
     * @param func_name - name of the invoked function.
     * @param msg - message to print.
     */
    inline void print_func_msg_if_debug(const string &func_name,
                                        const string &msg) {
        if (debug) {
            cerr() << func_name << msg << endl;
        }
    }

    /** @brief Wrapper function of @p enc_set_t member function @p clear.
     * Invoke member function @p clear on @p enc_set_t set with given id passed,
     * which clears set with given identifier.
     * Function assumes that set with given id exists.
     * @param id - identifier of a set whose member function @p clear is
     *             to be called.
     */
    void clear_set(unsigned long id) {
        id_to_enc_set()[id].clear();
    }

    /** @brief Wrapper function of @p id_to_enc_set_t member function @p erase.
     * Invoke member function @p erase on @p id_to_enc_set_t map with @p id passed,
     * which removes set with given identifier from the map.
     * Function assumes that set with given id exists.
     * @param id - identifier of a set to be erased.
     */
    void erase_set(unsigned long id) {
        id_to_enc_set().erase(id);
    }

    /** @brief Wrapper function of @p enc_set_t member function @p insert.
     * Invoke member function @p insert on @p enc_set_t set with @p value passed,
     * which inserts given value to set with specified id.
     * Function assumes that set with given id exists.
     * @param id - identifier of a set where passed value is to be inserted.
     * @param value - value to be inserted.
     */
    void insert_value(unsigned long id, const string &value) {
        id_to_enc_set()[id].insert(value);
    }

    /** @brief Wrapper function of @p enc_set_t member function @p erase.
     * Invoke member function @p erase on @p enc_set_t set with @p value passed,
     * which removed given value from the set with specified id.
     * Function assumes that set with given id exists and contains specified value.
     * @param id - identifier of a set from where passed value is to be removed.
     * @param value - value to be removed.
     */
    void erase_value(unsigned long id, const string &value) {
        id_to_enc_set()[id].erase(value);
    }

    /** @brief Check if set with given id is present.
     * @param id - identifier of a set whose presence it to be checked.
     * @return @p true if set with given id is present, @p false otherwise.
     */
    inline bool is_set_present(const unsigned long id) {
        return id_to_enc_set().find(id) != id_to_enc_set().end();
    }

    /** @brief Check if given encrypted value is present in the set with given id.
     * @param id - identifier of a set where given encrypted value is to be
     *             searched.
     * @param enc_value - encrypted value to be searched.
     * @return @p true if set with given id exists and contains passed encrypted
     * value, @p false otherwise.
     */
    inline bool is_value_present(const unsigned long id, const string &enc_value) {
        return is_set_present(id) &&
               id_to_enc_set()[id].find(enc_value) != id_to_enc_set()[id].end();
    }

    /** @brief Create C++ string representation understandable by the compiler
     * of passed C-style string.
     * @param str - C-style string whose representation is to be created.
     * @return string object of the form "str" if @p str is not @p nullptr,
     * "NULL" otherwise.
     */
    inline string string_repr(const char *str) {
        string enclosing = (str == nullptr ? "" : R"(")");
        return enclosing + (str == nullptr ? "NULL" : str) + enclosing;
    }

    /** @brief Create cyphered version of passed string.
     * Create new string @p cyphered_string where each character of the original
     * string is replaced with its hexadecimal representation of length two
     * and there are spaces inserted between any two consecutive characters
     * from the original string.
     * @param str - string to cypher.
     * @return Cyphered version of passed string in the form
     * @p cypher "cyphered_string".
     */
    string cypher(const string &str) {
        stringstream cyphered;
        cyphered << "cypher " << '"';

        size_t processed = 0;
        for (int c : str) {
            processed++;

            cyphered << std::uppercase << std::hex << c / 16 << c % 16;
            if (processed < str.length()) {
                cyphered << " ";
            }
        }

        cyphered << '"';
        return cyphered.str();
    }

    /** @brief Encrypt passed value with given key.
     * Create new string object whose content is passed value encrypted with
     * given key. Encryption is symmetric and is done by XOR operation. If given
     * key is shorter than the value, it is cyclically repeated. If given value
     * is @p nullptr, empty string is returned. If given key is @p nullptr or
     * is an empty string, no encryption is performed and copy of the passed value
     * is returned.
     * @param value - C-style string representing value to be encrypted.
     * @param key - C-style string representing key to be used in encryption.
     * @return @p string object whose content is passed value encrypted with given
     * key or empty string if passed value is @p nullptr or string object copy
     * of the passed value if given key is empty or is @p nullptr.
     */
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

    /** @brief Perform specified set operation and print diagnostic messages
     * if debug mode is on.
     * Print function call that invoked this function if debug mode is on.
     * Check if set with given is present. If so, perform specified operation
     * and print appropriate diagnostic message if debug mode is on. Otherwise,
     * only print appropriate diagnostic message if debug mode is on.
     * @param func_name - name of the function that invoked this function.
     * @param id - identifier of a set on which operation is to be performed.
     * @param msg_pair - @p msg_pair_t pair carrying diagnostic string messages
     *                   to be printed if debug mode is on: first one if set
     *                   exists, second one if set does not exist.
     * @param func_if_set_present - @p set_func_t pointer to function performing
     *                              operation on set with given id.
     */
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

    /** @brief Perform specified value operations and print diagnostic messages
     * if debug mode is on.
     * Print function call that invoked this function if debug mode is on.
     * Perform appropriate value operation, print appropriate diagnostic message
     * (if debug mode is on) and return appropriate value based if passed value
     * is present in the set with given id.
     * @param func_name - name of the function that invoked this function.
     * @param id - identifier of a set on which value operation is to be
     *             performed.
     * @param value - value on which operation is to be performed.
     * @param key - key used to encrypt passed value.
     * @param msg_pair - @p msg_pair_t pair carrying diagnostic string messages
     *                   to be printed if debug mode is on: first one if passed
     *                   value is valid C-style string and set with given id
     *                   exists and contains encrypted value, second one if above
     *                   conditions are true except that set with given id does not
     *                   contain encrypted value.
     * @param val_func_pair - @p val_func_pair_t pair carrying @p val_func_t
     *                        pointers to functions to be called, performing value
     *                        operations: first one if passed value is valid C-style
     *                        string and set with given id exists and contains
     *                        encrypted value, second one if above conditions
     *                        are true, except that set with given id does not
     *                        contain encrypted value.
     * @param res_pair - @p res_pair_t pair carrying return results of type @p bool:
     *                   first one if passed value is valid C-style string and set
     *                   with given id exists and contains encrypted value, second
     *                   one if above conditions are true, except that set with
     *                   given id does not contain encrypted value.
     * @return @p false if @p value is @p nullptr or set with given id does not
     * exist, otherwise @p res_pair.first when set with given id contains
     * encrypted value, otherwise @p res_pair.second.
     */
    bool handle_value_operation(const string &func_name, unsigned long id,
                                const char *value, const char *key,
                                const msg_pair_t &msg_pair,
                                const val_func_pair_t val_func_pair,
                                const res_pair_t res_pair) {
        if (debug) {
            cerr() << func_name << "(" << id << ", "
                   << string_repr(value) << ", " << string_repr(key) << ")" << endl;
        }

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
        id_to_enc_set().insert({added_sets(), new_set});

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
        msg << " contains " << id_to_enc_set()[id].size() << " element(s)";

        print_set_msg_if_debug("encstrset_size", id, msg.str());

        return id_to_enc_set()[id].size();
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
            for (const string &s : id_to_enc_set()[src_id]) {
                bool added = id_to_enc_set()[dst_id].insert(s).second;

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
