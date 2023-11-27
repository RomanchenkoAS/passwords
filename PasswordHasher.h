#pragma once

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

    bool validate(const std::string &input);

};


class HasherSHA256 : public AbstractPasswordHasher {
private:
    void initializeDigest(EVP_MD_CTX *digest_context) override;

public:
    using AbstractPasswordHasher::AbstractPasswordHasher;

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