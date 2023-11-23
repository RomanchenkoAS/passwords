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

using namespace std;

class User {
private:
    string username;
    string password_hash;
    string password_hint;
    bool authorized;
public:
    User() : authorized(false) {};

    ~User();
};