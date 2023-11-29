#pragma once

#include <string>
#include "Password.h"

class User {
private:
    std::string username;
    MasterPassword masterPassword;
    const std::string dataPath;

public:
//    New user constructor
    explicit User(const std::string &path) : dataPath(path) {};

//    Existing user constructor
    explicit User(std::string &username, const std::string &path) :
            username(username), dataPath(path), masterPassword() {};

    int authSequence(std::string &input);

    int registerSequence(std::string &new_username, std::string &new_password);

    [[nodiscard]] std::string getUsername() const { return username; }

    [[nodiscard]] std::string getEncryptionKey() const { return username + masterPassword.getHash(); }

    ~User() = default;
};