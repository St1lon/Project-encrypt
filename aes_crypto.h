#ifndef AES_MENU_H
#define AES_MENU_H

#include <iostream>
#include <vector>
#include <array>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

class AesMenu {
public:
    static void show_file_content(const string& filename);
    static void clear_key(array<unsigned char, 32>& key);
    static void generate_random_key(array<unsigned char, 32>& key);
    static bool encrypt_file(const string& input_file, const string& output_file,
        const array<unsigned char, 32>& key,
        const array<unsigned char, 16>& iv);
    static bool decrypt_file(const string& input_file, const string& output_file,
        const array<unsigned char, 32>& key,
        const array<unsigned char, 16>& iv);
};

#endif