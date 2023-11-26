#include <iostream>
#include <filesystem> // for getting data directory path
#include "Manager.cpp" // must be a headerfile

std::string getBasePath() {
    return std::filesystem::current_path().string();
}

int mainMenu() {
    int choice;
    std::cout << "\nHello!\n";
    std::cout << "1. Log in\n";
    std::cout << "2. Sign up\n";
    std::cout << "0. Exit\n";
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    return choice;
}

pair<string, string> logInMenu() {
    string username, password;
    std::cout << "\nUsername: ";
    std::cin >> username;
    std::cout << "Password: ";
    std::cin >> password;
    return make_pair(string(username), string(password));
}

pair<string, string> registerMenu() {
    string username, password = "1", passwordConfirmation = "2";
    while (true) {
        if (username.empty()) {
//            Skip entering username if it is already entered
            std::cout << "\nUsername: ";
            std::cin >> username;
        }
        std::cout << "Password: ";
        std::cin >> password;
        std::cout << "Confirm password: ";
        std::cin >> passwordConfirmation;
        if (password != passwordConfirmation) {
            std::cout << "Passwords don't match, try again.\n";
        } else {
            break;
        }
    }
    return make_pair(string(username), string(password));
}

int main() {

    const string basePath = getBasePath();
    const string dataDir = basePath + "/../data/";

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
                User *userPtr;
                try {
                    User user(username, password, dataDir);
                    user.authSequence(password);

                } catch (std::runtime_error &) {
                    cout << "\nUsername or password don't match.\n";
                    break;
                }
                if (userPtr->isAuthorized()) {
                    cout << "\nHello, " << username << "!\n";
                    Manager manager(userPtr, dataDir);
                    manager.initialize();
                    manager.menu();
                }
                break;
            }
            case 2: {
                auto [username, password] = registerMenu();
                User new_user(dataDir);
                int result = new_user.registerSequence(username, password);
                if (result == 1) {
                    std::cout << "\nUser already exists, choose a different username.";
                } else {
                    std::cout << "\nUser created, now log in with provided credentials.";
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