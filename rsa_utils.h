#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <string>

class RSAUtils {
public:
    static void generate_keys(long long& n, long long& e, long long& d);
    static std::string encrypt(const std::string& message, long long e, long long n);
    static std::string decrypt(const std::string& encrypted_message, long long d, long long n);
    static bool encrypt_file(const std::string& input_file, const std::string& output_file, long long e, long long n);
    static bool decrypt_file(const std::string& input_file, const std::string& output_file, long long d, long long n);
};

#endif