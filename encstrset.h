#ifndef ENCSTRSET_H
#define ENCSTRSET_H

#ifdef __cplusplus
#include <cstdio>
#else
#include <stddef.h>
#include <stdbool.h>
#endif

#ifdef __cplusplus
namespace jnp1 {
    extern "C" {
#endif

    /** @brief Create new set and return its identifier.
     * @return Non-negative integer uniquely identifying newly created set.
     */
    unsigned long encstrset_new();

    /** @brief Delete set with given id.
     * Delete set with given id. If set with given id does not exist, do nothing.
     * @param id - identifier of set to delete.
     */
    void encstrset_delete(unsigned long id);

    /** @brief Get size of the given set.
     * Get number of elements present in set with given identifier. If set with
     * given identifier does not exist, return 0.
     * @param id - identifier of set whose size is returned.
     * @return Number of elements present in set with given identifier or 0,
     * if set with given id does not exist.
     */
    size_t encstrset_size(unsigned long id);

    /** @brief Add encrypted value to set.
     * Add encrypted value to set with given id if set with given identifier does
     * exist and encrypted value is not present in this set. Otherwise, do nothing.
     * Encryption is symmetric and is done by XOR operation. If given key is
     * shorter than value, it is cyclically repeated.
     * @param id - identifier of a set where encrypted value is to be added.
     * @param value - value to encrypt and add to set.
     * @param key - key used to encrypt value.
     * @return @p true if encrypted value was successfully added, @p false
     * otherwise.
     */
    bool encstrset_insert(unsigned long id, const char *value, const char *key);

    /** @brief Remove encrypted value from set.
     * Remove encrypted value from set with given id if specified set exists
     * and encrypted value is present in this set. Otherwise, do nothing.
     * @param id - identifier of a set where encrypted value is to be removed.
     * @param value - value to encrypt and remove from set.
     * @param key - key used to encrypt value.
     * @return @p true if encrypted value was successfully removed, @p false
     * otherwise.
     */
    bool encstrset_remove(unsigned long id, const char *value, const char *key);

    /** @brief Test if encrypted value is present in set with given id.
     * @param id - identifier of a set where encrypted value is to be tested.
     * @param value - value to encrypt and test.
     * @param key - key used to encrypt value.
     * @return @p true if encrypted value is present in specified set, @p false
     * otherwise.
     */
    bool encstrset_test(unsigned long id, const char *value, const char *key);

    /** @brief Remove all elements from set with given id.
     * @param id - identifier of a set to clear.
     */
    void encstrset_clear(unsigned long id);

    /** @brief Copy all elements from first set to the other set.
     * Copy all elements from set with id @p src_id to set with id @p dst_id
     * if both sets exist. Otherwise, do nothing.
     * @param src_id - id of a set from where elements are to be copied.
     * @param dst_id - id of a set where elements are to be copied.
     */
    void encstrset_copy(unsigned long src_id, unsigned long dst_id);

#ifdef __cplusplus
    }
}
#endif

#endif // ENCSTRSET_H
