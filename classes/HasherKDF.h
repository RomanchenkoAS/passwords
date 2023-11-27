#pragma once

#include <iostream>
#include <openssl/kdf.h> // for ciphering data

//  Two-way encryptor/decryptor using Key Derivation Function (KDF)
class HasherKDF {
private:
//    Key derivation function
    static std::string deriveKey(const std::string &key);

//    Common initialization for encryption and decryption
    static void initializeCipher(EVP_CIPHER_CTX *ctx, const std::string &key, bool encrypting);

    static std::string toHex(const unsigned char *data, size_t length);

    static std::string fromHex(const std::string &hex);

public:
    HasherKDF() = default;

    // Encrypts the input string using the key
    [[nodiscard]] static std::string encrypt(const std::string &key, const std::string &input);

    // Decrypts the input string using the key
    [[nodiscard]] static std::string decrypt(const std::string &key, const std::string &inputHex);
};