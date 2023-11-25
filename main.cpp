#include <iostream>
#include "Manager.cpp"

using namespace std;

int main() {

    cout << "hello passworder" << endl;

    PasswordHasher hash("hello");
    cout << hash.getHash() << endl;
    return 0;


}