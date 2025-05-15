#include "rsa_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <sstream>

using namespace std;

bool isPrime(long long num) {
    if (num <= 1) return false;
    for (long long i = 2; i <= sqrt(num); i++) {
        if (num % i == 0) return false;
    }
    return true;
}

long long generatePrime() {
    long long prime;
    do {
        prime = rand() % 50 + 10;
    } while (!isPrime(prime));
    return prime;
}

long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

long long modInverse(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;

    if (m == 1) return 0;

    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) x1 += m0;

    return x1;
}

long long modExp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

void RSAUtils::generate_keys(long long& n, long long& e, long long& d) {
    srand(time(0));
    long long p = generatePrime();
    long long q = generatePrime();
    while (q == p) q = generatePrime();

    n = p * q;
    long long phi = (p - 1) * (q - 1);

    e = 2;
    while (e < phi && gcd(e, phi) != 1) e++;

    d = modInverse(e, phi);
}

string RSAUtils::encrypt(const string& message, long long e, long long n) {
    stringstream encrypted;
    for (char c : message) {
        long long encrypted_char = modExp(c, e, n);
        encrypted << encrypted_char << " ";
    }
    return encrypted.str();
}

string RSAUtils::decrypt(const string& encrypted_message, long long d, long long n) {
    stringstream ss(encrypted_message);
    string decrypted;
    long long num;
    while (ss >> num) {
        char decrypted_char = modExp(num, d, n);
        decrypted += decrypted_char;
    }
    return decrypted;
}

bool RSAUtils::encrypt_file(const string& input_file, const string& output_file, long long e, long long n) {
    ifstream in(input_file);
    if (!in) {
        cerr << "Нельзя открыть файл: " << input_file << endl;
        return false;
    }

    string message((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    string encrypted = encrypt(message, e, n);

    ofstream out(output_file);
    if (!out) {
        cerr << "Нельзя открыть файл: " << output_file << endl;
        return false;
    }

    out << encrypted;
    out.close();

    return true;
}

bool RSAUtils::decrypt_file(const string& input_file, const string& output_file, long long d, long long n) {
    ifstream in(input_file);
    if (!in) {
        cerr << "Нельзя открыть файл: " << input_file << endl;
        return false;
    }

    string encrypted_message((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    string decrypted = decrypt(encrypted_message, d, n);

    ofstream out(output_file);
    if (!out) {
        cerr << "Нельзя открыть файл: " << output_file << endl;
        return false;
    }

    out << decrypted;
    out.close();

    return true;
}