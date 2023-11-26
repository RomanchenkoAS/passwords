#ifndef PASSWORDS_HASHERKDF_H
#define PASSWORDS_HASHERKDF_H

#include <iostream>
#include <openssl/kdf.h> // for ciphering data

class HasherKDF {
//    Two-way encryptor/decryptor using Key Derivation Function (KDF)
private:
//    Key derivation function
    static std::string deriveKey(const std::string &key);

//    Common initialization for encryption and decryption
    static void initializeCipher(EVP_CIPHER_CTX *ctx, const std::string &key, bool encrypting);

public:
    HasherKDF() = default;

    // Encrypts the input string using the key
    [[nodiscard]] static std::string encrypt(const std::string &key, const std::string &input);

    // Decrypts the input string using the key
    [[nodiscard]] static std::string decrypt(const std::string &key, const std::string &inputHex);
};

#endif //PASSWORDS_HASHERKDF_H
