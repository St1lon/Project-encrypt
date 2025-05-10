#ifndef DES_UTILS_H
#define DES_UTILS_H

#include <vector>
#include <string>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

class DESUtils {
public:
    static std::vector<unsigned char> des_encrypt(const std::vector<unsigned char>& plaintext, const DES_cblock& key);
    static std::vector<unsigned char> des_decrypt(const std::vector<unsigned char>& ciphertext, const DES_cblock& key);
    static bool encrypt_file(const std::string& input_file, const std::string& output_file, const DES_cblock& key);
    static bool decrypt_file(const std::string& input_file, const std::string& output_file, const DES_cblock& key);
    static std::string base64_encode(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> base64_decode(const std::string& encoded);
    static void generate_random_key(DES_cblock* key);
};

#endif // DES_UTILS_H