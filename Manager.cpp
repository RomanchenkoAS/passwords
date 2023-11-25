// Password
//  Fields
//      label, text
//  Methods
//      getters/setters


// Manager
//  Fields
//      file
//      filename
//      user
//      Password: master_password
//      passwords vector

//  Methods
//      constructor takes username&password and opens file and calls readFromFile(master_password)
//      read from file - read file and decipher and fill passwords vector
//      create_password / delete_password / alter_password
//      user menu

// class User
// Fields
//    Username
//    Password: master_password
//    Password_hint

//    Settings
//      Autodestruct

// Methods
//    Getters/setters
//    Authorization: get username/password and open manager
//    Settings menu: set autodestruct, change password or hint
#include <string>
#include "Hasher.h"

using namespace std;

class BasePassword {
protected:
    string hash;
    string hint;
public:
//    Compare
};

class Password : public BasePassword {

};

class MasterPassword : public BasePassword {
public:
    MasterPassword() = default;

    explicit MasterPassword(string &username) {
//            Hash name
//            Find db with username
//            Read content of first line into hash
    }
};

class User {
private:
    string username;
    MasterPassword password;
    bool authorized;
public:
    explicit User(string &username) : username(username), authorized(false) {
//        Create a MasterPassword instance
    };

    void auth_sequence(string &input_password) {
//        Password input(input_password);
//        Create a Password instance
//        Validate against MasterPassword
//        Set auth = true
    };

    ~User();
};