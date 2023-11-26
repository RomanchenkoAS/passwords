#include <iostream>
#include "Manager.cpp" // must be a headerfile
#include "HasherKDF.h" // not needed here

using namespace std;

int main() {

    string username = "artur";

//    string name_hash = PasswordHasher(username).getHash();
//    cout << name_hash << endl;
//    cout << "Master password instance:\n";
//    MasterPassword mp(PasswordHasher(username).getHash());

    User user(username);
    string password = "1234";
    user.auth_sequence(password);
    if (user.isAuthorized()) {
        Manager manager(&user);
        manager.initialize();
        manager.displayPasswords();
    }

//    cout << "\n\nTesting encryptor:\n";
//
//    HasherKDF encryptor;
//    string key = "artur";
//    string value = "vk,999";
//    string encrypted_string = encryptor.encrypt(key, value);
//    cout << encrypted_string << endl;
//    string decrypted = encryptor.decrypt(key, encrypted_string);
//    cout << decrypted << endl;
//
//
//    key = "artur";
//    value = "google,123";
//    encrypted_string = encryptor.encrypt(key, value);
//    cout << encrypted_string << endl;
//    decrypted = encryptor.decrypt(key, encrypted_string);
//    cout << decrypted << endl;
//
//
//    key = "artur";
//    value = "yandex,567";
//    encrypted_string = encryptor.encrypt(key, value);
//    cout << encrypted_string << endl;
//    decrypted = encryptor.decrypt(key, encrypted_string);
//    cout << decrypted << endl;

    return 0;


}