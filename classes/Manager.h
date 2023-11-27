#pragma once

#include <string>
#include <vector>
#include <fstream> // files IO
#include <sstream> // for line by line reading
#include "PasswordHasher.h"
#include "HasherKDF.h"
#include "Password.h"
#include "User.h"

class Manager {
private:
    User *user;
    std::string filename;
    std::vector<Password> passwordsList;
    std::ifstream file;

public:
    explicit Manager(
            User *user, const std::string &path
    ) : user(user), filename(path + PasswordHasher(user->getUsername()).getHash()) {}

    static std::string decrypt(const std::string &key, std::string &line) {
        return HasherKDF::decrypt(key, line);
    };

    static std::string encrypt(const std::string &key, std::string &line) {
        return HasherKDF::encrypt(key, line);
    };

    static std::pair<std::string, std::string> parse(const std::string &line);

    void openFile();

    void initialize();

    void displayPasswords();

    void writePasswords();

    void createPassword(const std::string &name, const std::string &password);

    void createPasswordMenu();

    int deletePassword(int index);

    void deletePasswordMenu();

    void menu();
};