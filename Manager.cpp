#include <string>
#include <vector>
#include <filesystem> // for checking if a file exists
#include <fstream> // for reading/writing files
#include <sstream> // for line by line reading
#include <algorithm> // for transform(), remove_if()

#include "PasswordHasher.h"
#include "HasherKDF.h"

//using namespace std;


class BasePassword {
protected:
    std::string hash;
public:

    bool operator==(const BasePassword &other) const {
//        Password validation
        return this->hash == other.hash;
    }

    std::string getHash() {
        return hash;
    }

};

class Password : public BasePassword {
private:
    std::string name;
    std::string value;
public:
    Password() = delete;

    explicit Password(std::string name, std::string value) : name(std::move(name)), value(std::move(value)) {
//        For manager usage - store all values
    };

    explicit Password(const std::string &plaintextPassword) {
//        For authorization, does not store plaintext value
        hash = PasswordHasher(plaintextPassword).getHash();
    }

    void display() {
        std::cout << name << ": " << value << std::endl;
    }

    [[nodiscard]] std::string getCSV() const {
//        Return Comma Separated Value of password for writing in DB
        return name + "," + value;
    }

//    Unused
    [[nodiscard]] std::string getName() const { return name; }
};

class MasterPassword : public BasePassword {
private:
    std::string dataPath;
    std::string username;
public:
    MasterPassword() = default;

    int setPassword(const std::string &inputUsername, const std::string &path) {
        dataPath = path;
//        Find file with user's username for file name
        std::string nameHash = PasswordHasher(inputUsername).getHash();
        std::string filename = dataPath + nameHash;

        std::ifstream file(filename);
        if (!file) {
            return 1;
        }
//        Read content of first line into hash
        getline(file, hash);
        return 0;
    }

    [[nodiscard]] std::string getHash() const { if (!hash.empty()) return hash; }
};

class User {
private:
    std::string username;
    MasterPassword masterPassword;
    bool authorized;
    const std::string dataPath;
public:
    User(const std::string &path) : authorized(false), dataPath(path) {
//        New user constructor
    };

    explicit User(std::string &username, std::string &password, const std::string &path) :
            username(username), authorized(false), dataPath(path), masterPassword() {
//        Existing user constructor
    };

    int authSequence(std::string &input) {
        if (masterPassword.setPassword(username, dataPath) == 0) {
            Password inputPassword(input);
            if (inputPassword == masterPassword) {
                authorized = true;
                return 0;
            }
        }
        return 1;
    };

    int registerSequence(std::string &new_username, std::string &new_password) {
        std::string nameHash = PasswordHasher(new_username).getHash();
        std::string filename = dataPath + nameHash;
        if (std::filesystem::exists(filename)) {
            return 1;
        } else {
//            Create a file for this user
            std::ofstream createdFile(filename);
            if (!createdFile) {
                throw std::runtime_error("Failed to create file: " + filename);
            }
            createdFile << Password(new_password).getHash();
            createdFile.close();
            return 0;
        }
    }

    [[nodiscard]] std::string getUsername() const { return username; }

    [[nodiscard]] std::string getEncryptionKey() const { return username + masterPassword.getHash(); }

    [[nodiscard]] bool isAuthorized() const { return authorized; }

    ~User() = default;
};


class Manager {
private:
    User *user;
    std::string filename;
    std::vector<Password> passwordsList;
    std::ifstream file;

public:
    explicit Manager(User *user, const std::string &path) : user(user),
                                                            filename(path +
                                                                     PasswordHasher(user->getUsername()).getHash()) {
    }

    static std::string decrypt(const std::string &key, std::string &line) {
        return HasherKDF::decrypt(key, line);
    };

    static std::string encrypt(const std::string &key, std::string &line) {
        return HasherKDF::encrypt(key, line);
    };

    static std::pair<std::string, std::string> parse(const std::string &line) {
//        Parse comma separated std::string into three values
        std::stringstream ss(line);
        std::string s1, s2;

        if (getline(ss, s1, ',') && getline(ss, s2, ',')) {
            return make_pair(s1, s2);
        } else {
            throw std::runtime_error("Invalid line format");
        }
    }

    void openFile() {
        file.open(filename);
        if (!file) {
            throw std::runtime_error("Failed to open " + filename + " for reading.");
        }
    };

    void initialize() {
//        Read passwords from file and create Password instances
        openFile();
        if (file.is_open()) {
            // Skip the first line that contains master password
            std::string temp;
            getline(file, temp);

            std::string line;
            while (getline(file, line)) {
                line = decrypt(user->getEncryptionKey(), line);
                const auto [name, value] = parse(line);
                passwordsList.push_back(Password(name, value));
            }
            file.close();
        } else {
            throw std::runtime_error("Failed to open " + filename + " for reading.");
        }
    };

    void displayPasswords() {
        if (passwordsList.empty()) {
            std::cout << std::endl << "No passwords in " << user->getUsername() << "'s manager yet.\n";
            return;
        }
        std::cout << std::endl << user->getUsername() << "'s passwords: \n";
        for (int i = 0; i < passwordsList.size(); i++) {
            std::cout << i + 1 << ". ";
            passwordsList[i].display();
        }
    }

    void writePasswords() {
//        Overwrite content of user passwords file
        std::ifstream infile(filename);
        if (!infile) {
            throw std::runtime_error("Failed to open " + filename + " for reading.");
        }

//        To keep master password hash
        std::string masterPasswordHash;
        getline(infile, masterPasswordHash);
        infile.close();

        std::ofstream outfile(filename);
        if (!outfile) {
            throw std::runtime_error("Failed to open " + filename + " for writing.");
        }

//        Write master password hash back to the file
        outfile << masterPasswordHash << std::endl;

        for (const auto &password: passwordsList) {
            std::string passwordCSV = password.getCSV();
            std::string encryptedLine = encrypt(user->getEncryptionKey(), passwordCSV);
            std::transform(encryptedLine.begin(), encryptedLine.end(), encryptedLine.begin(), ::toupper);
            outfile << encryptedLine << std::endl;
        }

        outfile.close();
    }

    void createPassword(const std::string &name, const std::string &password) {
        passwordsList.push_back(Password(name, password));
        writePasswords();
    }

    void createPasswordMenu() {
        std::string name, password;
        std::cout << "\nName: ";
        std::cin >> name;
        std::cout << "Password: ";
        std::cin >> password;
        createPassword(name, password);
    }

    int deletePassword(int index) {
        if (index < passwordsList.size()) {
            passwordsList.erase(passwordsList.begin() + index);
            writePasswords();
            return 0;
        } else {
            return 1;
        }
    }

    void deletePasswordMenu() {
        if (passwordsList.empty()) {
            std::cout << std::endl << "No passwords in " << user->getUsername() << "'s manager yet.\n";
            return;
        }
        int index;
        std::cout << "\nIndex of password to delete (0 to cancel action): ";
        std::cin >> index;
        if (index == 0) {
            std::cout << "Action canceled." << std::endl;
        } else {
            int status = deletePassword(index - 1);
            if (status == 1) {
                std::cout << "Invalid index." << std::endl;
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