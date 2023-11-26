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
    cout << encrypter.encrypt("artur", "vk: 999") << endl;
    cout << encrypter.decrypt("artur", "74fa20a9a45f623e8a9d724cd7f45759") << endl;

    return 0;


}