#include "des_utils.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <iomanip>
#include <cmath>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <fstream>
#include <openssl/rand.h>
using namespace std;

vector<unsigned char> DESUtils::des_encrypt(const vector<unsigned char>& plaintext, const DES_cblock& key) {
    DES_key_schedule key_schedule;
    DES_cblock key_copy;
    memcpy(key_copy, key, sizeof(DES_cblock));

    if (DES_set_key_checked(&key_copy, &key_schedule)) {
        cerr << "Weak key detected!" << endl;
        return {};
    }
    size_t pad_len = 8 - (plaintext.size() % 8);
    vector<unsigned char> padded(plaintext);
    padded.insert(padded.end(), pad_len, static_cast<unsigned char>(pad_len));

    vector<unsigned char> ciphertext(padded.size());
    for (size_t i = 0; i < padded.size(); i += 8) {
        DES_ecb_encrypt(
            reinterpret_cast<const_DES_cblock*>(&padded[i]),
            reinterpret_cast<DES_cblock*>(&ciphertext[i]),
            &key_schedule,
            DES_ENCRYPT
        );
    }

    return ciphertext;
}

vector<unsigned char> DESUtils::des_decrypt(const vector<unsigned char>& ciphertext, const DES_cblock& key) {
    if (ciphertext.size() % 8 != 0) {
        cerr << "Invalid ciphertext size (must be multiple of 8)" << endl;
        return {};
    }

    DES_key_schedule key_schedule;
    
    // Копируем ключ
    DES_cblock key_copy;
    memcpy(key_copy, key, sizeof(DES_cblock));
    
    // Устанавливаем ключ
    if (DES_set_key_checked(&key_copy, &key_schedule)) {
        cerr << "Weak key detected!" << endl;
        return {};
    }

    vector<unsigned char> plaintext(ciphertext.size());

    for (size_t i = 0; i < ciphertext.size(); i += 8) {
        DES_cblock input_block, output_block;
        memcpy(&input_block, &ciphertext[i], 8);
        
        DES_ecb_encrypt(
            &input_block,
            &output_block,
            &key_schedule,
            DES_DECRYPT
        );
        
        // Копируем результат обратно в вектор
        memcpy(&plaintext[i], &output_block, 8);
    }
    // Удаляем padding PKCS#7
    size_t pad_len = plaintext.back();
    if (pad_len > 0 && pad_len <= 8) {
        plaintext.resize(plaintext.size() - pad_len);
    }

    return plaintext;
}


string DESUtils::base64_encode(const vector<unsigned char>& data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    
    char *encoded_data = nullptr;
    long encoded_size = BIO_get_mem_data(mem, &encoded_data);
    
    string result(encoded_data, encoded_size);
    
    BIO_free_all(b64);
    return result;
}

vector<unsigned char> DESUtils::base64_decode(const string& encoded) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(encoded.data(), encoded.size());
    BIO_push(b64, mem);
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    vector<unsigned char> decoded(encoded.size());
    int decoded_size = BIO_read(b64, decoded.data(), encoded.size());
    decoded.resize(decoded_size);
    
    BIO_free_all(b64);
    return decoded;
}

bool DESUtils::encrypt_file(const string& input_file, const string& output_file, const DES_cblock& key) {
    ifstream in(input_file, ios::binary);
    if (!in) {
        cerr << "Cannot open input file: " << input_file << endl;
        return false;
    }

    vector<unsigned char> plaintext((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    auto ciphertext = des_encrypt(plaintext, key);
    if (ciphertext.empty()) {
        return false;
    }

    string base64_ciphertext = base64_encode(ciphertext);

    ofstream out(output_file);
    if (!out) {
        cerr << "Cannot open output file: " << output_file << endl;
        return false;
    }

    out << base64_ciphertext;
    out.close();

    return true;
}

bool DESUtils::decrypt_file(const string& input_file, const string& output_file, const DES_cblock& key) {
    ifstream in(input_file);
    if (!in) {
        cerr << "Cannot open input file: " << input_file << endl;
        return false;
    }

    string base64_ciphertext((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    auto ciphertext = base64_decode(base64_ciphertext);
    auto plaintext = des_decrypt(ciphertext, key);
    if (plaintext.empty()) {
        return false;
    }

    ofstream out(output_file, ios::binary);
    if (!out) {
        cerr << "Cannot open output file: " << output_file << endl;
        return false;
    }

    out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    out.close();

    return true;
}

// В des_utils.h


// В des_utils.cpp
void DESUtils::generate_random_key(DES_cblock* key) {
    if (!key) {
        throw std::invalid_argument("Key pointer is null");
    }
    
    if (RAND_bytes(*key, sizeof(DES_cblock)) != 1) {
        throw std::runtime_error("Ошибка генерации ключа");
    }
    
    for (auto& byte : *key) {
        byte &= 0xFE;
        byte |= __builtin_parity(byte) ^ 1;
    }
}