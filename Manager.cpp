#include <string>
#include <vector>
#include <fstream> // for reading/writing files
#include <sstream> // for line by line reading
#include <algorithm> // for transform(), remove_if()

#include "PasswordHasher.h"
#include "HasherKDF.h"

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

    [[nodiscard]] string getCSV() const {
//        Return Comma Separated Value of password for writing in DB
        return name + "," + value;
    }

    [[nodiscard]] string getName() const { return name; }
};

class MasterPassword : public BasePassword {
private:
    string dataPath;
public:
    MasterPassword() = default;

    void setPassword(const string &username) {
//            Find file with user's username for file name
        string name_hash = PasswordHasher(username).getHash();
        string filename = dataPath + name_hash;

        ifstream file(filename);
        if (!file) {
            throw std::runtime_error("Data for this user is not found.");
        }
//            Read content of first line into hash
        getline(file, hash);
    }

    explicit MasterPassword(const string &username, const string &path) : dataPath(path) {
        setPassword(username);
    }

    [[nodiscard]] string getHash() const { if (!hash.empty()) return hash; }
};

class User {
private:
    string username;
    MasterPassword master_password;
    bool authorized;
    const string dataPath;
public:
    explicit User(string &username, const string &path) : username(username), authorized(false), dataPath(path),
                                                          master_password(username, path) {
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
    explicit Manager(User *user, const string &path) : user(user),
                                                       filename(path + PasswordHasher(user->getUsername()).getHash()) {
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

    void openFile() {
        file.open(filename);
        if (!file) {
            throw runtime_error("Failed to open " + filename + " for reading.");
        }
    };

    void initialize() {
//        Read passwords from file and create Password instances
        openFile();
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
            file.close();
        } else {
            throw runtime_error("Failed to open " + filename + " for reading.");
        }
    };

    void displayPasswords() {
        cout << endl << user->getUsername() << "'s passwords: \n";
        for (int i = 0; i < passwords_list.size(); i++) {
            cout << i + 1 << ". ";
            passwords_list[i].display();
        }
    }

    void writePasswords() {
//        Overwrite content of user passwords file
        ifstream infile(filename);
        if (!infile) {
            throw runtime_error("Failed to open " + filename + " for reading.");
        }

//        To keep master password hash
        string masterPasswordHash;
        getline(infile, masterPasswordHash);
        infile.close();

        ofstream outfile(filename);
        if (!outfile) {
            throw runtime_error("Failed to open " + filename + " for writing.");
        }

//        Write master password hash back to the file
        outfile << masterPasswordHash << endl;

        for (const auto &password: passwords_list) {
            string passwordCSV = password.getCSV();
            string encryptedLine = encrypt(user->getEncryptionKey(), passwordCSV);
            std::transform(encryptedLine.begin(), encryptedLine.end(), encryptedLine.begin(), ::toupper);
            outfile << encryptedLine << endl;
        }

        outfile.close();
    }

    void createPassword(const string &name, const string &password) {
        passwords_list.push_back(Password(name, password));
        writePasswords();
    }

    void createPasswordMenu() {
        string name, password;
        cout << "Name: ";
        cin >> name;
        cout << "Password: ";
        cin >> password;
        createPassword(name, password);
    }

    int deletePassword(int index) {
        if (index < passwords_list.size()) {
            passwords_list.erase(passwords_list.begin() + index);
            writePasswords();
            return 0;
        } else {
            return 1;
        }
    }

    void deletePasswordMenu() {
        int index;
        cout << "\nIndex of password to delete (0 to cancel action): ";
        cin >> index;
        if (index == 0) {
            cout << "Action canceled." << endl;
        } else {
            int status = deletePassword(index - 1);
            if (status == 1) {
                cout << "Invalid index." << endl;
            }
        }
    };


    void menu() {
        int choice;
        do {
            std::cout << "\nMenu:\n";
            std::cout << "1. Display passwords\n";
            std::cout << "2. Add password\n";
            std::cout << "3. Delete password\n";
            std::cout << "0. Exit\n";
            std::cout << "Enter your choice: ";
            std::cin >> choice;

            switch (choice) {
                case 1: {
                    displayPasswords();
                    break;
                }
                case 2: {
                    createPasswordMenu();
                    break;
                }
                case 3: {
                    deletePasswordMenu();
                    break;
                }
                case 0: {
                    break;
                }
                default: {
                    std::cout << "Invalid choice. Please try again.\n";
                }
            }
        } while (choice != 0);
    }
};