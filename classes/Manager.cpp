#include <iostream>
#include <algorithm> // for transform(), remove_if()
#include <filesystem> // for checking if a file exists
#include "Manager.h"
#include "PasswordHasher.h"
#include "Password.h"


std::pair<std::string, std::string> Manager::parse(const std::string &line) {
//    Parse comma separated std::string into three values
    std::stringstream ss(line);
    std::string s1, s2;

    if (getline(ss, s1, ',') && getline(ss, s2, ',')) {
        return make_pair(s1, s2);
    } else {
        throw std::runtime_error("Invalid line format");
    }
}

void Manager::openFile() {
    file.open(filename);
    if (!file) {
        throw std::runtime_error("Failed to open " + filename + " for reading.");
    }
};

void Manager::initialize() {
//    Read passwords from file and create Password instances
    openFile();
    if (file.is_open()) {
//        Skip the first line that contains master password
        std::string temp;
        getline(file, temp);

        std::string line;
        while (getline(file, line)) {
            try {
                line = decrypt(user->getEncryptionKey(), line);
            } catch (const std::runtime_error &error) {
                throw std::runtime_error("Failed to decrypt content. Check credentials and filename.");
            }
            const auto [name, value] = parse(line);
            passwordsList.push_back(Password(name, value));
        }
        file.close();
    } else {
        throw std::runtime_error("Failed to open " + filename + " for reading.");
    }
};

void Manager::displayPasswords() {
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

void Manager::writePasswords() {
//    Overwrite content of user passwords file
    std::ifstream infile(filename);
    if (!infile) {
        throw std::runtime_error("Failed to open " + filename + " for reading.");
    }

//    To keep master password hash
    std::string masterPasswordHash;
    getline(infile, masterPasswordHash);
    infile.close();

    std::ofstream outfile(filename);
    if (!outfile) {
        throw std::runtime_error("Failed to open " + filename + " for writing.");
    }

//    Write master password hash back to the file
    outfile << masterPasswordHash << std::endl;

    for (const auto &password: passwordsList) {
        std::string passwordCSV = password.getCSV();
        std::string encryptedLine;
        try {
            encryptedLine = encrypt(user->getEncryptionKey(), passwordCSV);
        } catch (const std::runtime_error &error) {
            throw std::runtime_error("Failed to encrypt content. Check credentials and filename.");
        }
        std::transform(encryptedLine.begin(), encryptedLine.end(), encryptedLine.begin(), ::toupper);
        outfile << encryptedLine << std::endl;
    }

    outfile.close();
}

void Manager::createPassword(const std::string &name, const std::string &password) {
    passwordsList.push_back(Password(name, password));
    writePasswords();
}

void Manager::createPasswordMenu() {
    std::string name, password;
    std::cout << "\nName: ";
    std::cin >> name;
    std::cout << "Password: ";
    std::cin >> password;
    createPassword(name, password);
}

int Manager::deletePassword(int index) {
    if (index < passwordsList.size()) {
        passwordsList.erase(passwordsList.begin() + index);
        writePasswords();
        return 0;
    } else {
        return 1;
    }
}

void Manager::deletePasswordMenu() {
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


void Manager::menu() {
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