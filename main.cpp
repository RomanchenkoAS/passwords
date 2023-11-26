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

    cout << "\n\nTesting encrypter:\n";

    HasherKDF encrypter;
    string key = "artur";
    string value = "vk,999";
    string encrypted_string = encrypter.encrypt(key, value);
    cout << encrypted_string << endl;

    string decrypted = encrypter.decrypt(key, encrypted_string);
    cout << decrypted << endl;

    return 0;


}