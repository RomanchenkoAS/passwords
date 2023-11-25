#ifndef HASHER_H
#define HASHER_H

#include <string>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <utility> // for std::move()
#include <sstream> // for operating with string as a stream


class AbstractHasher {
protected:
    std::string binary_hash;
    std::string hash;
    std::string filename;
    std::ifstream file;

    void toHex();

    virtual void initializeDigest(EVP_MD_CTX *digest_context) = 0;

    void calculateHash();

public:
    explicit AbstractHasher(std::string filename) : filename(std::move(filename)),
                                                    file(this->filename, std::ios::binary) {
        if (!static_cast<std::ifstream&>(file).is_open()) {
            throw std::runtime_error("Cannot open file");
        }
    };

//    Forbid copy
    AbstractHasher(const AbstractHasher &) = delete;

    AbstractHasher &operator=(const AbstractHasher &) = delete;

//    Forbid move
    AbstractHasher(AbstractHasher &&) = delete;

    AbstractHasher &operator=(AbstractHasher &&) = delete;


    virtual ~AbstractHasher() = default;

    void checkHash();

    std::string getHash();

    std::string getBinaryHash();

    void showBinaryHash();

    void showHash();

    bool validate(const std::string &input);

    virtual std::string getMethod() = 0;

};


class HasherSHA256 : public AbstractHasher {
private:
    void initializeDigest(EVP_MD_CTX *digest_context) override;

public:
    using AbstractHasher::AbstractHasher;
    std::string getMethod() override { return "SHA256"; }

};


class PasswordHasher : public HasherSHA256 {
public:
    explicit PasswordHasher(const std::string& input) : HasherSHA256("tempfile") {
        // Write 'input' to a temporary file
        std::ofstream tempFile("tempfile");
        tempFile << input;
        tempFile.close();

        calculateHash();
        // Delete temporary file
        std::remove("tempfile");
    }

    bool operator==(const std::string& other) {
        return validate(other);
    }
};


#endif //HASHER_H
