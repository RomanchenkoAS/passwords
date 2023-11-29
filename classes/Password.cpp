#include <string>
#include "Password.h"
#include "PasswordHasher.h"

bool BasePassword::operator==(const BasePassword &other) const {
//    Password validation
    return this->hash == other.hash;
}

Password::Password(const std::string &plaintextPassword) {
//    For authorization, does not store plaintext value
    hash = PasswordHasher(plaintextPassword).getHash();
}

void Password::display() {
    std::cout << name << ": " << value << std::endl;
}

[[nodiscard]] std::string Password::getCSV() const {
//    Return Comma Separated Value of password for writing in DB
    return name + "," + value;
}

int MasterPassword::setPassword(const std::string &inputUsername, const std::string &path) {
    dataPath = path;
//    Find file with user's username for file name
    std::string nameHash = PasswordHasher(inputUsername).getHash();
    std::string filename = dataPath + nameHash;

    std::ifstream file(filename);
    if (!file) {
        return 1;
    }
//    Read content of first line into hash
    getline(file, hash);
    file.close();
    return 0;
}