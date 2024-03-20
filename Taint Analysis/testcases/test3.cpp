#include <iostream>

using namespace std;

// Switch
int main() {
    int x;
    cin >> x; // Tainted = {x}

    int result;
    switch (x) {
        case 1:
            result = 10; // Tainted = {x}
            break;
        case 2:
            result = 20; // Tainted = {x}
            break;
        case 3:
            result = 30; // Tainted = {x}
            break;
        default:
            result = 0; // Tainted = {x}
            break;
    }
    
    return result; // Tainted = {x}

}
