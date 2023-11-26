#ifndef PASSWORD_HASHER_H
#define PASSWORD_HASHER_H

#include <string>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <utility> // for std::move()
#include <sstream> // for operating with string as a stream


class AbstractPasswordHasher {
protected:
    std::string binary_hash;
    std::string hash;
    std::string input;

    void toHex();

    virtual void initializeDigest(EVP_MD_CTX *digest_context) = 0;

    void calculateHash();

public:
    explicit AbstractPasswordHasher(std::string &input_string) : input(input_string) {};

//    Forbid copy
    AbstractPasswordHasher(const AbstractPasswordHasher &) = delete;

    AbstractPasswordHasher &operator=(const AbstractPasswordHasher &) = delete;

//    Forbid move
    AbstractPasswordHasher(AbstractPasswordHasher &&) = delete;

    AbstractPasswordHasher &operator=(AbstractPasswordHasher &&) = delete;

    virtual ~AbstractPasswordHasher() = default;

    void checkHash();

    std::string getHash();

    std::string getBinaryHash();

    void showBinaryHash();

    void showHash();

    bool validate(const std::string &input);

    virtual std::string getMethod() = 0;

};


class HasherSHA256 : public AbstractPasswordHasher {
private:
    void initializeDigest(EVP_MD_CTX *digest_context) override;

public:
    using AbstractPasswordHasher::AbstractPasswordHasher;

    std::string getMethod() override { return "SHA256"; }

};


class PasswordHasher : public HasherSHA256 {
public:
    explicit PasswordHasher(std::string input) : HasherSHA256(input) {
        calculateHash();
    }

    bool operator==(const std::string &other) {
        return validate(other);
    }
};

#endif //PASSWORD_HASHER_H
