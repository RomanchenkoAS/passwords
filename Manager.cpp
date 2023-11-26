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


#include <string>
#include <fstream> // for reading data from files
#include <sstream> // for line by line reading

#include "PasswordHasher.h"

using namespace std;

class BasePassword {
protected:
    string hash;
    string hint;
public:

    bool operator==(const BasePassword &other) const {
//        Password validation
        return this->hash == other.hash;
    }

    string getHash() {
        return hash;
    }

    void setHint(string& new_hint) {
        hint = new_hint;
    }

    [[nodiscard]] string getHint() const {return hint;}
};

class Password : public BasePassword {
public:
    Password() = delete;

    explicit Password(const string &plaintext_password) {
        hash = PasswordHasher(plaintext_password).getHash();
    }
};

class MasterPassword : public BasePassword {
public:
    MasterPassword() = default;

    void setPassword(const string &username) {
        cout << "username = " << username << endl;
        string name_hash = PasswordHasher(username).getHash();
//            Find db with username
        cout << "name_hash = " << name_hash << endl;
//        TODO todo todo
        string filename = "/home/artur/dev/passwords/cmake-build-debug/" + name_hash;
        cout << "filename = " << filename << endl;

        ifstream file(filename);
        if (!file) {
            throw std::runtime_error("Data for this user is not found.");
        }
//            Read content of first line into hash
        getline(file, hash);
        cout << "hash = " << hash << endl;
    }

    explicit MasterPassword(const string &username) {
        setPassword(username);
    }
};

class User {
private:
    string username;
    MasterPassword master_password;
    bool authorized;
public:
    explicit User(string &username) : username(username), authorized(false), master_password() {
        try {
            master_password.setPassword(username);
        }
        catch (const runtime_error &error) {
            throw std::runtime_error("Failed to initialize user: " + string(error.what()));
        }
    };

    void auth_sequence(string &input) {
        Password input_password(input);
        if (input_password == master_password) {
            authorized = true;
        }
    };

    [[nodiscard]] string getUsername() const { return username; }

    [[nodiscard]] bool isAuthorized() const { return authorized; }

    ~User() = default;
};


class Manager {
private:
    User *user;
    string filename;
public:
    explicit Manager(User *user) : user(user), filename(PasswordHasher(user->getUsername()).getHash()) {
        cout << "Manager created\n";
    }
};