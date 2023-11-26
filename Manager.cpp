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



#include <string>
#include <fstream> // for reading data from files
#include <sstream> // for line by line reading
#include <utility>
#include <vector>


#include "PasswordHasher.h"
#include "HasherKDF.h"

using namespace std;

const string BASE_PATH = "/home/artur/dev/passwords/cmake-build-debug/";


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

    void setHint(string &new_hint) {
        hint = new_hint;
    }

    [[nodiscard]] string getHint() const { return hint; }
};

class Password : public BasePassword {
private:
    string name;
    string value;
public:
    Password() = delete;

    explicit Password(string name, string value) : name(std::move(name)), value(std::move(value)) {
//        For manager usage - store all values
    };

    explicit Password(const string &plaintext_password) {
//        For authorization, does not store plaintext value
        hash = PasswordHasher(plaintext_password).getHash();
    }

    void display() {
        cout << name << ": " << value << endl;
    }
};

class MasterPassword : public BasePassword {
public:
    MasterPassword() = default;

    void setPassword(const string &username) {
        string name_hash = PasswordHasher(username).getHash();
//            Find db with username
//        TODO SOLVE ISSUE WITH BASE PATH
        string filename = BASE_PATH + name_hash;

        ifstream file(filename);
        if (!file) {
            throw std::runtime_error("Data for this user is not found.");
        }
//            Read content of first line into hash
        getline(file, hash);
    }

    explicit MasterPassword(const string &username) {
        setPassword(username);
    }

    [[nodiscard]] string getHash() const { if (!hash.empty()) return hash; }
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

    [[nodiscard]] string getEncryptionKey() const { return username + master_password.getHash(); }

    [[nodiscard]] bool isAuthorized() const { return authorized; }

    ~User() = default;
};


class Manager {
private:
    User *user;
    string filename;
    vector<Password> passwords_list;
    ifstream file;

public:
    explicit Manager(User *user) : user(user), filename(PasswordHasher(user->getUsername()).getHash()) {
//        cout << "Manager created\n";
    }

    static string decrypt(const string &key, string &line) {
        return HasherKDF::decrypt(key, line);
    };

    static string encrypt(const string &key, string &line) {
        return HasherKDF::encrypt(key, line);
    };

    static pair<string, string> parse(const string &line) {
//        Parse comma separated string into three values
        stringstream ss(line);
        string s1, s2;

        if (getline(ss, s1, ',') && getline(ss, s2, ',')) {
            return make_pair(s1, s2);
        } else {
            throw std::runtime_error("Invalid line format");
        }
    }

    void open_file() {
        file.open(filename);
        if (!file) {
            throw runtime_error("Failed to open " + filename);
        }
    };

    void initialize() {
        open_file();
        if (file.is_open()) {
            // Skip the first line that contains master password
            string temp;
            getline(file, temp);

            string line;
            while (getline(file, line)) {
                line = decrypt(user->getEncryptionKey(), line);
                const auto [name, value] = parse(line);
                passwords_list.push_back(Password(name, value));
            }
        }
    };

    void displayPasswords() {
        for (int i = 0; i < passwords_list.size(); i++) {
            cout << i + 1 << ". ";
            passwords_list[i].display();
        }
    }

    //      constructor takes username&password and opens file and calls readFromFile(master_password)
//      read from file - read file and decipher and fill passwords vector
//      create_password / delete_password / alter_password
//      user menu
};