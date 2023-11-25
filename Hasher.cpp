#include "Hasher.h"

// Functions implementation go here
#include <algorithm> // for std::transform()
#include <fstream>
#include <iomanip> // for input/output manipulation (toHex)

#include <bitset> // for debugging

void AbstractHasher::toHex() {
    // Transform binary hash string into hexadecimal
#ifdef DEBUG
    std::cout << "Binary string:" << std::endl;
    for (unsigned char c: binary_hash) {
        std::bitset<8> bits(c);
        std::cout << bits << ' ';
    }
    std::cout << std::endl;
#endif
    std::stringstream ss;
    for (char byte: binary_hash) {
        /*
         * (int)(unsigned char)(byte) - transform a signed char to unsigned and then into an integer 0..255
         * std::setw(2) - set length of a hex digit to 2 slots
         * std::setfill('0') - fill slots with 0 if empty up to 2 slots
         * std::hex - interpret input as a hexadecimal string
         */
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) (unsigned char) (byte);
    }
    hash = ss.str();
    std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
}

void AbstractHasher::calculateHash() {
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    if (digest_context == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
//        Initialize digest operation
    initializeDigest(digest_context);

//        Process chunks of data and update hash_array
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        if (EVP_DigestUpdate(digest_context, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(digest_context);
            throw std::runtime_error("Failed to update digest");
        }
    }

//        Finish processing hash_array
    unsigned char hash_array[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (EVP_DigestFinal_ex(digest_context, hash_array, &lengthOfHash) != 1) {
//            Free memory
        EVP_MD_CTX_free(digest_context);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(digest_context);

//        Turn to string and generate hexadecimal hash_array
    binary_hash = std::string(reinterpret_cast<const char *>(hash_array), lengthOfHash);
    toHex();
};

void AbstractHasher::checkHash() {
//        Make sure hash is already generated
    if (binary_hash.empty()) {
        calculateHash();
    }
}

std::string AbstractHasher::getHash() {
    checkHash();
    return hash;
}

std::string AbstractHasher::getBinaryHash() {
    checkHash();
    return binary_hash;
}

void AbstractHasher::showBinaryHash() {
    checkHash();
    for (unsigned char c: binary_hash) {
        std::bitset<8> bits(c);
        std::cout << bits << ' ';
    }
    std::cout << std::endl;
}

void AbstractHasher::showHash() {
    std::cout << getHash() << std::endl;
}

bool AbstractHasher::validate(const std::string &input) {
    checkHash();
//    Uppercase input string
    std::string compare_string = input;
    std::transform(compare_string.begin(), compare_string.end(), compare_string.begin(), ::toupper);
    return (hash == compare_string);
}


void HasherSHA256::initializeDigest(EVP_MD_CTX *digest_context) {
    if (EVP_DigestInit_ex(digest_context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(digest_context);
        throw std::runtime_error("Failed to initialize digest context");
    }
}

