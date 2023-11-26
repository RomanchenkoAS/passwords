#include <iostream>
#include "Manager.cpp"

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
        Manager(&user, user.getFilename());
    }
    return 0;


}