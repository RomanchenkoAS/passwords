#pragma once
#include <string>

class BasePassword {
protected:
    std::string hash;

public:
    bool operator==(const BasePassword &other) const;

    [[nodiscard]] std::string getHash() const { return hash; }

    virtual ~BasePassword() = default;
};

class Password : public BasePassword {
private:
    std::string name;
    std::string value;

public:
    Password() = delete;

//    For manager usage - store all values
    explicit Password(std::string name, std::string value) : name(std::move(name)), value(std::move(value)) {};

//    For authorization, does not store plaintext value
    explicit Password(const std::string &plaintextPassword);

    void display();

    [[nodiscard]] std::string getCSV() const;

    ~Password() override = default;
};

class MasterPassword : public BasePassword {
private:
    std::string dataPath;
    std::string username;

public:
    MasterPassword() = default;

    int setPassword(const std::string &inputUsername, const std::string &path);

    ~MasterPassword() override = default;
};
