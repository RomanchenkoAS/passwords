#include <filesystem> // to check if directory exists
#include "User.h"
#include "PasswordHasher.h"

int User::authSequence(std::string &input) {
    if (masterPassword.setPassword(username, dataPath) == 0) {
        Password inputPassword(input);
        if (inputPassword == masterPassword) {
            return 0;
        }
    }
    return 1;
};

int User::registerSequence(std::string &new_username, std::string &new_password) {
    std::string nameHash = PasswordHasher(new_username).getHash();
    std::string filename = dataPath + nameHash;
    if (std::filesystem::exists(filename)) {
        return 1;
    } else {
//        Create a file for this user
        std::ofstream createdFile(filename);
        if (!createdFile) {
            throw std::runtime_error("Failed to create file: " + filename);
        }
        createdFile << Password(new_password).getHash();
        createdFile.close();
        return 0;
    }
}
