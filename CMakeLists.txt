cmake_minimum_required(VERSION 3.22)
project(passwords)

# Find the OpenSSL package
find_package(OpenSSL REQUIRED)

# Include the OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})

set(CMAKE_CXX_STANDARD 17)

add_executable(
        passwords
        classes/Manager.h
        classes/Manager.cpp
        classes/PasswordHasher.h
        classes/PasswordHasher.cpp
        classes/HasherKDF.h
        classes/HasherKDF.cpp
        classes/Password.h
        classes/Password.cpp
        classes/User.h
        classes/User.cpp
        main.cpp
)

# Link OpenSSL to executable
target_link_libraries(passwords OpenSSL::SSL OpenSSL::Crypto)