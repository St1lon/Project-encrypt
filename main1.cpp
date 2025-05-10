#include <iostream>
#include <string>
#include "des_utils.h"
#include "rsa_utils.h"
#include "aes_crypto.h"
#include <cmath>
#include <vector>
#include <ctime>
#include <sstream>
#include <fstream>
#include <string.h>
#include <limits>
#include <iomanip>
using namespace std;

string readFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Не удалось открыть файл: " + filename);
    }
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    return content;
}

void writeFile(const string& filename, const string& content) {
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("Не удалось создать файл: " + filename);
    }
    file << content;
    file.close();
}
void ShowFile(const string& filename){
   ifstream file(filename);
   if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            cout << line << endl;
        }
        file.close();
    } else {
        cerr << "Нельзя открыть файл" << endl;
    }
}

void clear_key(DES_cblock& key) {
    memset(key, 0, sizeof(DES_cblock));
}

void des_menu() {
    DES_cblock key;
    bool key_initialized = false;
    int choice;
    
    while (true) {
        cout << "\nМеню DES:\n";
        cout << "1. Шифровать файл\n";
        cout << "2. Расшифровать файл\n";
        cout << "0. Выход\n";
        cout << "Выбор: ";
        cin >> choice;

        if (choice == 0) break;

        if (choice == 1) {
            while(true) {
                string input_file, output_file;
                int t;
                cout << "\nОперации шифрования:\n";
                cout << "1. Ввести ключ\n";
                cout << "2. Сгенерировать ключ\n";
                cout << "3. Выполнить шифрование\n";
                cout << "0. Назад\n";
                cout << "Выбор: ";
                cin >> t;
                
                if(t == 0) break;
                
                switch(t) {
                    case 1: {
                        cout << "Введите 8-байтный ключ (16 шестнадцатеричных символов): ";
                        string key_str;
                        cin >> key_str;
                        
                        if(key_str.length() != 16) {
                            cout << "Ошибка: ключ должен быть 16 символов (8 байт)!\n";
                            break;
                        }
                        
                        bool valid = true;
                        for(char c : key_str) {
                            if(!isxdigit(c)) {
                                valid = false;
                                break;
                            }
                        }
                        
                        if(!valid) {
                            cout << "Ошибка: ключ должен содержать только шестнадцатеричные символы (0-9, a-f)!\n";
                            break;
                        }
                        
                        for(int i = 0; i < 8; i++) {
                            string byte_str = key_str.substr(i*2, 2);
                            key[i] = static_cast<unsigned char>(stoul(byte_str, nullptr, 16));
                        }
                        
                        key_initialized = true;
                        cout << "Ключ успешно установлен: ";
                        for(int i = 0; i < 8; i++) {
                            printf("%02x ", key[i]);
                        }
                        cout << endl;
                        break;
                    }
                    case 2:
                        DESUtils::generate_random_key(&key);
                        key_initialized = true;
                        cout << "Новый ключ сгенерирован: ";
                        for(int i = 0; i < 8; i++) {
                            printf("%02x ", key[i]);
                        }
                        cout << "\nСохраните этот ключ для последующего дешифрования!\n";
                        break;
                    case 3:
                        if(!key_initialized) {
                            cout << "Ошибка: ключ не установлен!\n";
                            break;
                        }
                        
                        cout << "Используемый ключ: ";
                        for(int i = 0; i < 8; i++) {
                            printf("%02x", key[i]);
                        }
                        cout << endl;
                        
                        cout << "Введите входной файл: ";
                        cin >> input_file;
                        cout << "Содержимое входного файла: \n";
                        ShowFile(input_file);
                        cout << "Введите выходной файл: ";
                        cin >> output_file;
                        
                        if (DESUtils::encrypt_file(input_file, output_file, key)) {
                            cout << "Файл успешно зашифрован!\n";
                            cout << "Содержимое выходного файла: \n";
                            ShowFile(output_file);
                            clear_key(key);
                            key_initialized = false;
                        } else {
                            cout << "Ошибка при шифровании!\n";

                        }
                        break;
                    default:
                        cout << "Неверный выбор!\n";
                }
            }
        } else if (choice == 2) {
            if(!key_initialized) {
                cout << "Введите 8-байтный ключ (16 шестнадцатеричных символов): ";
                string key_str;
                cin >> key_str;
                
                if(key_str.length() != 16) {
                    cout << "Ошибка: ключ должен быть 16 символов (8 байт)!\n";
                    continue;
                }
                
                bool valid = true;
                for(char c : key_str) {
                    if(!isxdigit(c)) {
                        valid = false;
                        break;
                    }
                }
                
                if(!valid) {
                    cout << "Ошибка: ключ должен содержать только шестнадцатеричные символы (0-9, a-f)!\n";
                    continue;
                }
                
                for(int i = 0; i < 8; i++) {
                    string byte_str = key_str.substr(i*2, 2);
                    key[i] = static_cast<unsigned char>(stoul(byte_str, nullptr, 16));
                }
                
                key_initialized = true;
            }
            
            cout << "Используемый ключ: ";
            for(int i = 0; i < 8; i++) {
                printf("%02x", key[i]);
            }
            cout << endl;
            
            string input_file, output_file;
            cout << "Введите зашифрованный файл: ";
            cin >> input_file;
            cout << "Содержимое зашифрованного файла: \n";
            ShowFile(input_file);
            cout << "Введите файл для сохранения результата: ";
            cin >> output_file;
            
            if (DESUtils::decrypt_file(input_file, output_file, key)) {
                cout << "Файл успешно дешифрован!\n";
                cout << "Содержимое выходного файла: \n";
                ShowFile(output_file);
                clear_key(key);
                key_initialized = false;
            } else {
                cout << "Ошибка при дешифровании!\n";

            }
        }
    }
}

void rsa_menu() {
    long long n = 0, e = 0, d = 0;
    bool key_loaded = false;
    int choice;

    while (true) {
        cout << "\nМеню RSA:\n";
        cout << "1. Шифровать файл\n";
        cout << "2. Дешифровать файл\n";
        cout << "3. Очистить текущий ключ\n";
        cout << "0. Выход\n";
        cout << "Выбор: ";
        cin >> choice;

        if (choice == 0) break;

        if (choice == 1) {
            while(true) {
                string input_file, output_file;
                int t;
                cout << "\nОперации шифрования:\n";
                cout << "1. Ввести ключ\n";
                cout << "2. Сгенерировать ключ\n";
                cout << "3. Выполнить шифрование\n";
                cout << "0. Назад\n";
                cout << "Выбор: ";
                cin >> t;
                
                if(t == 0) break;
                
                switch(t) {
                    case 1: {
                        cout << "Введите ключ в формате 'n e d': ";
                        if(cin >> n >> e >> d) {
                            key_loaded = true;
                            cout << "Открытый ключ (n, e): (" << n << ", " << e << ")\n";
                            cout << "Закрытый ключ (n, d): (" << n << ", " << d << ")\n";
                        } else {
                            cout << "Ошибка ввода ключа!\n";
                            cin.clear();
                            cin.ignore( numeric_limits< streamsize>::max(), '\n');
                        }
                        break;
                    }
                    case 2: {
                        RSAUtils::generate_keys(n, e, d);
                        key_loaded = true;
                        cout << "\n";
                        cout << "Открытый ключ (n, e): (" << n << ", " << e << ")\n";
                        cout << "Закрытый ключ (n, d): (" << n << ", " << d << ")\n";
                        cout << "Сохраните ключ самостоятельно!" << endl;
                        break;
                    }
                    case 3: {
                        if (!key_loaded) {
                            cout << "Ошибка: ключ не загружен!\n";
                            break;
                        }
                        
                        cout << "Используется открытый ключ (n, e): (" << n << ", " << e << ")\n";
                        cout << "Введите входной файл: ";
                        cin >> input_file;
                        cout << "Содержимое входного файла: \n";
                        ShowFile(input_file);
                        cout << "Введите выходной файл: ";
                        cin >> output_file;
                        
                        if (RSAUtils::encrypt_file(input_file, output_file, e, n)) {
                            cout << "Файл успешно зашифрован!\n";
                            cout << "Содержимое выходного файла: \n";
                            ShowFile(output_file);
                        } else {
                            cout << "Ошибка при шифровании!\n";
                        }
                        n = e = d = 0;
                        key_loaded = false;
                        break;
                    }
                    default:
                        cout << "Неверный выбор!\n";
                }
            }
        } 
        else if (choice == 2) {
            if (!key_loaded) {
                cout << "Введите ключ в формате 'n e d': ";
                if(cin >> n >> e >> d) {
                    key_loaded = true;
                    cout << "Открытый ключ (n, e): (" << n << ", " << e << ")\n";
                    cout << "Закрытый ключ (n, d): (" << n << ", " << d << ")\n";
                } else {
                    cout << "Ошибка ввода ключа!\n";
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    continue;
                }
            }
            
            string input_file, output_file;
            cout << "Используется закрытый ключ (n, d): (" << n << ", " << d << ")\n";
            cout << "Введите зашифрованный файл: ";
            cin >> input_file;
            cout << "Содержимое зашифрованного файла: \n";
            ShowFile(input_file);
            cout << "Введите файл для сохранения результата: ";
            cin >> output_file;
            
            if (RSAUtils::decrypt_file(input_file, output_file, d, n)) {
                cout << "Файл успешно дешифрован!\n";
                cout << "Содержимое выходного файла: \n";
                ShowFile(output_file);
            } else {
                cout << "Ошибка при расшифровании!\n";
            }
            n = e = d = 0;
            key_loaded = false;
        }
        
    }
}

void aes_menu() {
    array<unsigned char, 32> key{};
    array<unsigned char, 16> iv{};
    bool key_initialized = false;
    bool iv_initialized = false;
    int choice;

    while (true) {
        cout << "\nМеню AES-256:\n";
        cout << "1. Шифровать файл\n";
        cout << "2. Расшифровать файл\n";
        cout << "0. Выход\n";
        cout << "Выбор: ";
        cin >> choice;

        if (choice == 0) break;

        if (choice == 1) {
            while (true) {
                string input_file, output_file;
                int sub_choice;
                cout << "\nОперации шифрования:\n";
                cout << "1. Ввести ключ (32 байта)\n";
                cout << "2. Сгенерировать ключ\n";
                cout << "3. Ввести IV (16 байт)\n";
                cout << "4. Сгенерировать IV\n";
                cout << "5. Выполнить шифрование\n";
                cout << "0. Назад\n";
                cout << "Выбор: ";
                cin >> sub_choice;

                if (sub_choice == 0) break;

                switch (sub_choice) {
                case 1: {
                    cout << "Введите 64-символьный ключ (32 байта в hex): ";
                    string key_str;
                    cin >> key_str;

                    if (key_str.length() != 64) {
                        cout << "Ошибка: ключ должен быть 64 символа (32 байта)!\n";
                        break;
                    }

                    for (int i = 0; i < 32; i++) {
                        string byte_str = key_str.substr(i * 2, 2);
                        key[i] = static_cast<unsigned char>(stoul(byte_str, nullptr, 16));
                    }

                    key_initialized = true;
                    cout << "Ключ установлен.\n";
                    break;
                }
                case 2:
                    AesMenu::generate_random_key(key);
                    key_initialized = true;
                    cout << "Сгенерирован ключ: ";
                    for (auto byte : key) {
                        cout <<  hex << setw(2) << setfill('0') << (int)byte;
                    }
                    cout << "\nСохраните его!\n";
                    break;
                case 3: {
                    cout << "Введите 32-символьный IV (16 байт в hex): ";
                    string iv_str;
                    cin >> iv_str;

                    if (iv_str.length() != 32) {
                        cout << "Ошибка: IV должен быть 32 символа (16 байт)!\n";
                        break;
                    }

                    for (int i = 0; i < 16; i++) {
                        string byte_str = iv_str.substr(i * 2, 2);
                        iv[i] = static_cast<unsigned char>(stoul(byte_str, nullptr, 16));
                    }

                    iv_initialized = true;
                    cout << "IV установлен.\n";
                    break;
                }
                case 4:
                    RAND_bytes(iv.data(), 16);
                    iv_initialized = true;
                    cout << "Сгенерирован IV: ";
                    for (auto byte : iv) {
                        cout <<  hex << setw(2) << setfill('0') << (int)byte;
                    }
                    cout << "\nСохраните его!\n";
                    break;
                case 5:
                    if (!key_initialized || !iv_initialized) {
                        cout << "Ошибка: ключ и IV должны быть установлены!\n";
                        break;
                    }

                    cout << "Введите входной файл: ";
                    cin >> input_file;
                    cout << "Содержимое файла:\n";
                    AesMenu::show_file_content(input_file);

                    cout << "Введите выходной файл: ";
                    cin >> output_file;

                    if (AesMenu::encrypt_file(input_file, output_file, key, iv)) {
                        cout << "Файл зашифрован!\n";
                        cout << "Результат:\n";
                        AesMenu::show_file_content(output_file);
                    }
                    else {
                        cout << "Ошибка шифрования!\n";
                    }
                    break;
                default:
                    cout << "Неверный выбор!\n";
                }
            }
        }
        else if (choice == 2) {
            if (!key_initialized) {
                cout << "Введите 64-символьный ключ (32 байта в hex): ";
                string key_str;
                cin >> key_str;

                if (key_str.length() != 64) {
                    cout << "Ошибка: ключ должен быть 64 символа (32 байта)!\n";
                    continue;
                }

                for (int i = 0; i < 32; i++) {
                    string byte_str = key_str.substr(i * 2, 2);
                    key[i] = static_cast<unsigned char>(stoul(byte_str, nullptr, 16));
                }

                key_initialized = true;
            }

            if (!iv_initialized) {
                cout << "Введите 32-символьный IV (16 байт в hex): ";
                string iv_str;
                cin >> iv_str;

                if (iv_str.length() != 32) {
                    cout << "Ошибка: IV должен быть 32 символа (16 байт)!\n";
                    continue;
                }

                for (int i = 0; i < 16; i++) {
                    string byte_str = iv_str.substr(i * 2, 2);
                    iv[i] = static_cast<unsigned char>(stoul(byte_str, nullptr, 16));
                }

                iv_initialized = true;
            }

            string input_file, output_file;
            cout << "Введите зашифрованный файл: ";
            cin >> input_file;
            cout << "Содержимое файла:\n";
            AesMenu::show_file_content(input_file);

            cout << "Введите файл для результата: ";
            cin >> output_file;

            if (AesMenu::decrypt_file(input_file, output_file, key, iv)) {
                cout << "Файл расшифрован!\n";
                cout << "Результат:\n";
                AesMenu::show_file_content(output_file);
            }
            else {
                cout << "Ошибка расшифрования!\n";
            }
        }
    }
}

int main() {
    system("chcp 65001");
    int algorithm_choice;
    string filename, content;
    while (true) {
        cout << "\nГлавное меню:\n";
        cout << "1. Использовать DES\n";
        cout << "2. Использовать RSA\n";
        cout << "3. Использование AES\n";
        cout << "4. Создание файла\n";
        cout << "0. Выход\n";
        cout << "Выбор: ";
        cin >> algorithm_choice;

        if (algorithm_choice == 0) break;

        switch (algorithm_choice) {
            case 1:
                des_menu();
                break;
            case 2:
                rsa_menu();
                break;
            case 3:
                aes_menu();
                break;
            case 4:
               cout << "Введите название файла :";
               cin >> filename;
               cin.get();  // Пропускаем один символ (обычно '\n')
               cout << "Введите сообщение: ";
               getline(cin, content);
               writeFile(filename, content);
               cout << "Содержимое файла " << filename << ":\n";
               ShowFile(filename);
               break;
            default:
                cout << "Неверный выбор!\n";
        }
    }
    return 0;
}