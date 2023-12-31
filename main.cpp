#include <iostream>
#include <filesystem> // for getting data directory path
#include "classes/Manager.h"
#include "classes/User.h"

std::string getBasePath() {
    return std::filesystem::current_path().string();
}

int mainMenu() {
    int choice;
    std::cout << "\n----- Hello! -----\n";
    std::cout << "1. Log in\n";
    std::cout << "2. Sign up\n";
    std::cout << "0. Exit\n";
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    return choice;
}

std::pair<std::string, std::string> logInMenu() {
    std::string username, password;
    std::cout << "\nUsername: ";
    std::cin >> username;
    std::cout << "Password: ";
    std::cin >> password;
    return make_pair(std::string(username), std::string(password));
}

std::pair<std::string, std::string> registerMenu() {
    std::string username, password1 = "1", password2 = "2";
    while (password1 != password2) {
        if (username.empty()) {
//            Skip entering username if it is already entered
            std::cout << "\nUsername: ";
            std::cin >> username;
        }
        std::cout << "Password: ";
        std::cin >> password1;
        std::cout << "Confirm password: ";
        std::cin >> password2;
        if (password1 != password2) {
            std::cout << "Passwords don't match, try again.\n";
        }
    }
    return make_pair(std::string(username), std::string(password1));
}

int main() {

    const std::string basePath = getBasePath();
    const std::string dataDir = basePath + "/../data/";
    std::cout << "data dir full path = " << dataDir << std::endl;

    // Make sure dataDir exists
    if (!std::filesystem::exists(dataDir)) {
        std::filesystem::create_directories(dataDir);
    }

    int choice = 0;
    do {
        choice = mainMenu();
        switch (choice) {
            case 1: {
                auto [username, password] = logInMenu();
                User user(username, dataDir);

                try {
                    if (user.authSequence(password) == 1) {
                        std::cout << "\nInvalid username or password. " << std::endl;
                    } else {
                        std::cout << "\nHello, " << username << "!\n";
                        Manager manager(&user, dataDir);
                        manager.initialize();
                        manager.menu();
                    }
                } catch (const std::runtime_error &error) {
                    std::cout << "\nError: " << error.what() << std::endl;
                }
                break;
            }
            case 2: {
                auto [username, password] = registerMenu();
                User new_user(dataDir);

                try {
                    if (new_user.registerSequence(username, password) == 1) {
                        std::cout << "\nUser already exists, choose a different username.";
                    } else {
                        std::cout << "\nUser created, now log in with provided credentials.\n";
                    }
                } catch (const std::runtime_error &error) {
                    std::cout << "\nInvalid username or password. " << std::endl;
                }
                break;
            }
            case 0: {
                break;
            }
            default: {
                std::cout << "Invalid choice. Please try again.\n";
            }
        }
    } while (choice != 0);

    return 0;
}