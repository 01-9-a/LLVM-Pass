#include <iostream>

using namespace std;

// Loops
int main() {
    int size; // Tainted = {}
    int x = 1; // Tainted = {}
    cin >> size; // Tainted = {size}
    for (int i = 0; i < size; i ++) { // Tainted = {size}
        x += size; // Tainted = {size, x}
    } // Tainted = {size, x}
    size = 10; // Tainted = {x}
    return x; // Tainted = {x}
}
