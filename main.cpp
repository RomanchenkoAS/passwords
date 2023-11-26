#include <iostream>
#include <filesystem> // for getting data directory path
#include "Manager.cpp" // must be a headerfile

using namespace std;

std::string getBasePath() {
    return std::filesystem::current_path().string();
}

int main() {

    const string basePath = getBasePath();
    const string dataDir = basePath + "/../data/";

    // Check if dataDir exists
    if (!std::filesystem::exists(dataDir)) {
        std::filesystem::create_directories(dataDir);
    }


    string username = "artur";
    User user(username, dataDir);
    string password = "1234";
    user.authSequence(password);
    if (user.isAuthorized()) {
        Manager manager(&user, dataDir);
        manager.initialize();
//        manager.displayPasswords();
//        manager.writePasswords();
        manager.menu();
    }


    return 0;


}