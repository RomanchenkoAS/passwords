#include "HasherKDF.h"

#include <iomanip> // for toHex and fromHex manipulations
#include <openssl/evp.h>

std::string HasherKDF::toHex(const unsigned char *data, size_t length) {
//    Transform data binary string into hexadecimal
    std::stringstream ss;

//    Convert the data pointer into a string
    std::string binaryString(reinterpret_cast<const char *>(data), length);

    for (unsigned char byte: binaryString) {
        /*
         * (int)(unsigned char)(byte) - transform a signed char to unsigned and then into an integer 0..255
         * std::setw(2) - set length of a hex digit to 2 slots
         * std::setfill('0') - fill slots with 0 if empty up to 2 slots
         * std::hex - interpret input as a hexadecimal string
         */
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str();
}

std::string HasherKDF::fromHex(const std::string &hex) {
//    Read binary string from hexadecimal
    std::string bytes;

//    Final line must be 1/2 of source since hexadecimal symbols go in pairs
    bytes.reserve(hex.size() / 2);

//    For each two characters do:
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) (std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string HasherKDF::deriveKey(const std::string &key) {
//    From key string create a key to fit KDF functions
    std::string derivedKey = key;
    derivedKey.resize(EVP_MAX_KEY_LENGTH, 0); // Pad or trim the key to fit EVP_MAX_KEY_LENGTH
    return derivedKey;
}

void HasherKDF::initializeCipher(EVP_CIPHER_CTX *ctx, const std::string &key, bool encrypting) {
//    EVP_CIPHER_CTX *ctx - this is a digest context object
//    const std::string &key - encryption/decryption key composed of username and password
//    bool encrypting - flag that marks if we are encrypting or decrypting

//    Create cipher context from key
    if (!EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), nullptr, reinterpret_cast<const unsigned char *>(key.data()),
                           nullptr, encrypting)) {
        throw std::runtime_error("Cipher initialization failed");
    }
}

std::string HasherKDF::encrypt(const std::string &key, const std::string &input) {
//    Create context object
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

//    Initialize context from key
    std::string derivedKey = deriveKey(key);
    initializeCipher(ctx, derivedKey, true);  // true for encryption

//    Set correct size of processed text
    std::string ciphertext;
    ciphertext.resize(input.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;

//    Add to digest context
    if (!EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]), &len,
                          reinterpret_cast<const unsigned char *>(input.data()), input.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }

//    Finalize digest context
    int finalLen = 0;
    if (!EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(&ciphertext[len]), &finalLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final block encryption failed");
    }

    ciphertext.resize(len + finalLen);

//    Deallocate memory
    EVP_CIPHER_CTX_free(ctx);

//    Transform to hexadecimal before return
    return toHex(reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size());
}

std::string HasherKDF::decrypt(const std::string &key, const std::string &inputHex) {
//    Get proper binary line from hexadecimal
    std::string input = fromHex(inputHex);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    std::string derivedKey = deriveKey(key);
    initializeCipher(ctx, derivedKey, false);  // false for decryption

    std::string plaintext;
    plaintext.resize(input.size());
    int len = 0;

    if (!EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char *>(&plaintext[0]), &len,
                          reinterpret_cast<const unsigned char *>(input.data()), input.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }

    int finalLen = 0;
    if (!EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(&plaintext[len]), &finalLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final block decryption failed");
    }

    plaintext.resize(len + finalLen);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}