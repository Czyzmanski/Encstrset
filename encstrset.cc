/*TODO: 
 * zmiania using namespace i bibliotek
 * najebanie komów
 */

#include <bits/stdc++.h>
using namespace std;

using hashes = unordered_set<string>;

namespace {
	
	static bool silent_mode = false;
	static unsigned long used = 0;
	static unordered_map<unsigned  long, hashes> encrypted;
	
	#define NAME(x) ((x) == nullptr ? "" : "\042") << ((x) == nullptr ? "NULL" : (x)) << ((x) == nullptr ? "" : "\042")
	
	#define ZERO_ARGS() "()"
	#define ONE_ARGS(x) "(" << x << ")"
	#define TWO_ARGS(x, y) "(" << x << ", " << y << ")"
	#define THREE_ARGS(x, y, z) "(" << x << ", " << y << ", " << z << ")"
	
	#define SET(id) "set #" << id
	
	#define INITIAL_CHECK														\
		if (debug && !silent_mode) {											\
			cerr << func << THREE_ARGS(id, NAME(value), NAME(key)) << endl;		\
		}																		\
		if (value == nullptr) {													\
			if (debug && !silent_mode) {										\
				cerr << func << ": invalid value (NULL)" << endl;				\
			}																	\
			return false;														\
		}																		\
		if (!exist_set(id)) {													\
			if (debug && !silent_mode) {										\
				cerr << func << ": " << SET(id) << " does not exist" << endl;	\
			}																	\
			return false;														\
		}																		\
		
	#define REWRITING					\
		string new_value;				\
		rewrite(value, new_value);		\
		string new_key;					\
		rewrite(key, new_key);			\
		encrypt(new_value, new_key);	\
	
	
	#ifdef NDEBUG
		static const bool debug = false;
	#else
		static const bool debug = true;
	#endif
	
	char hex16(int x) {
		if (x < 10) {
			return x + '0';
		}
		return x + 'A' - 10;
	}
	
	static string cypher(const string& s) {
		int n = 0;
		cerr << "cypher ";
		cerr << '"';
		for (int c : s) {
			n++;
			cerr << hex16(c / 16) << hex16(c % 16);
			if (n < (int)s.length()) {
				cerr << " ";
			}
		}
		cerr << '"';
		return "";
	}
	
	static bool exist_set(const unsigned long id) {
		return encrypted.find(id) != encrypted.end();
	}
	
	static bool exist_key(const unsigned id, const string& s) {
		return exist_set(id) && encrypted[id].find(s) != encrypted[id].end();
	}
	
	static void encrypt(string& s, const string& key) {
		if (!key.empty()) {
			int n = 0;
			for (int i = 0; i < (int)s.length(); i++) {
				s[i] ^= key[n];
				n = (n + 1) % key.size();
			}
		}
	}
	
	static void rewrite(const char* src, string& dst) {
		if (src == nullptr) {
			dst = "";
		}
		else {
			dst = src;
		}
	}	
}

unsigned long encstrset_new() {
	string func = "encstrset_new";
	
	if (debug) {
		cerr << func << ZERO_ARGS() << endl;
	}
	hashes new_set;
	encrypted.insert(make_pair(used, new_set));
	if (debug) {
		assert(exist_set(used));
		cerr << func << ": " << SET(used) << " created" << endl;
	}
	used++;
	return used - 1;
}

void encstrset_delete(unsigned long id) {
	string func = "encstrset_delete";
	
	if (debug) {
		cerr << func << ONE_ARGS(id) << endl;
	}
	if (exist_set(id)) {
		encrypted.erase(id);
		if (debug) {
			cerr << func << ": " << SET(id) << " deleted" << endl;
		}
	}
	else {
		if (debug) {
			cerr << func << ": " << SET(id) << " does not exist" << endl;
		}
	}
	if (debug) {
		assert(!exist_set(id));
	}
}

size_t encstrset_size(unsigned long id) {
	string func = "encstrset_size";
	
	if (debug) {
		cerr << func << ONE_ARGS(id) << endl;
	}
	if (!exist_set(id)) {
		if (debug) {
			cerr << func << ": " << SET(id) << " does not exist" << endl;
		}
		return 0;
	}
	if (debug) {
		cerr << func << ": " << SET(id) << " contains " << (unsigned long)encrypted[id].size() << " element(s)" << endl;
	}
	return encrypted[id].size();
}

bool encstrset_insert(unsigned long id, const char* value, const char* key) {
	string func = "encstrset_insert";
	INITIAL_CHECK;
	REWRITING;
	
	if (exist_key(id, new_value)) {
		if (debug && !silent_mode) {
			cerr << func << ": " << SET(id) << ", " << cypher(new_value) << " was already present" << endl;
		}
		return false;
	}
	encrypted[id].insert(new_value);
	if (debug && !silent_mode) {
		cerr << func << ": " << SET(id) << ", " << cypher(new_value) << " inserted" << endl;
	}
	return true;
}

bool encstrset_remove(unsigned long id, const char* value, const char* key) {
	string func = "encstrset_remove";
	INITIAL_CHECK;
	REWRITING;
	
	if (!exist_key(id, new_value)) {
		if (debug) {
			cerr << func << ": " << SET(id) << ", " << cypher(new_value) << " was not present" << endl;
		}
		return false;
	}
	encrypted[id].erase(new_value);
	if (debug) {
		cerr << func << ": " << SET(id) << ", " << cypher(new_value) << " removed" << endl;
	}
	return true;
}

bool encstrset_test(unsigned long id, const char* value, const char* key) {
	string func = "encstrset_test";
	INITIAL_CHECK;
	REWRITING;
	
	if (!exist_key(id, new_value)) {
		if (debug) {
			cerr << func << ": " << SET(id) << ", " << cypher(new_value) << " is not present" << endl;
		}
		return false;
	}
	if (debug) {
		cerr << func << ": " << SET(id) << ", " << cypher(new_value) << " is present" << endl;
	}
	return true;
}
	
void encstrset_clear(unsigned long id) {
	string func = "encstrset_clear";
	if (debug) {
		cerr << func << ONE_ARGS(id) << endl;
	}
	
	if (!exist_set(id)) {
		if (debug) {
			cerr << func << ": " << SET(id) << " does not exist" << endl;
		}
		return;
	}
	encrypted[id].clear();
	if (debug) {
		cerr << func << ": " << SET(id) << " cleared" << endl;
	}
}

void encstrset_copy(unsigned long src_id, unsigned long dst_id) {
	string func = "encstrset_copy";
	if (debug) {
		cerr << func << TWO_ARGS(src_id, dst_id) << endl;
	}
	if (!exist_set(src_id)) {
		if (debug) {
			cerr << func << ": " << SET(src_id) << " does not exist" << endl;
		}
		return;
	}
	if (!exist_set(dst_id)) {
		if (debug) {
			cerr << func << ": " << SET(dst_id) << " does not exist" << endl;
		}
		return;
	}
	
	silent_mode = true;
	for (string s : encrypted[src_id]) {
		if (encstrset_insert(dst_id, s.c_str(), nullptr)) {
			if (debug) {
				cerr << func << ": " << cypher(s) << " copied from " << SET(src_id) << " to " << SET(dst_id) << endl;
			}
		}
		else {
			if (debug) {
				cerr << func << ": copied " << cypher(s) << " was already present in " << SET(dst_id) << endl;
			}
		}
	}
	silent_mode = false;
}		
