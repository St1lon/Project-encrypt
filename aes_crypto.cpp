#include "aes_crypto.h"
#include <iomanip>
using namespace std;

void AesMenu::show_file_content(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cout << "Файл не удалось открыть!\n";
        return;
    }

    vector<unsigned char> buffer(
        (istreambuf_iterator<char>(file)),
        istreambuf_iterator<char>()
    );

    for (auto byte : buffer) {
        cout << hex << setw(2) << setfill('0') << (int)byte << " ";
    }
    cout << "\n";
}

void AesMenu::clear_key(array<unsigned char, 32>& key) {
    fill(key.begin(), key.end(), 0);
}

void AesMenu::generate_random_key(array<unsigned char, 32>& key) {
    RAND_bytes(key.data(), 32);
}

bool AesMenu::encrypt_file(const string& input_file, const string& output_file,
    const array<unsigned char, 32>& key,
    const array<unsigned char, 16>& iv) {
    ifstream in(input_file, ios::binary);
    ofstream out(output_file, ios::binary);

    if (!in || !out) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    vector<unsigned char> in_buffer(1024);
    vector<unsigned char> out_buffer(1024 + EVP_MAX_BLOCK_LENGTH);
    int bytes_read, out_len;

    while ((bytes_read = in.read(reinterpret_cast<char*>(in_buffer.data()), in_buffer.size()).gcount()) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buffer.data(), &out_len, in_buffer.data(), bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write(reinterpret_cast<char*>(out_buffer.data()), out_len);
    }

    if (EVP_EncryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write(reinterpret_cast<char*>(out_buffer.data()), out_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool AesMenu::decrypt_file(const string& input_file, const string& output_file,
    const array<unsigned char, 32>& key,
    const array<unsigned char, 16>& iv) {
    ifstream in(input_file, ios::binary);
    ofstream out(output_file, ios::binary);

    if (!in || !out) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    vector<unsigned char> in_buffer(1024);
    vector<unsigned char> out_buffer(1024 + EVP_MAX_BLOCK_LENGTH);
    int bytes_read, out_len;

    while ((bytes_read = in.read(reinterpret_cast<char*>(in_buffer.data()), in_buffer.size()).gcount()) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buffer.data(), &out_len, in_buffer.data(), bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write(reinterpret_cast<char*>(out_buffer.data()), out_len);
    }

    if (EVP_DecryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write(reinterpret_cast<char*>(out_buffer.data()), out_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}
