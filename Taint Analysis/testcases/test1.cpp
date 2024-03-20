#include <iostream>

using namespace std;

// Recursive calls
int recursive(int a) {
    int b = a + 15;
    if (a > 10) {
        b --;
        return recursive(b);
    } else {
        return a;
    }
}

int main() {
    int x; // Tainted = {}
    cin >> x; // Tainted = {x}
    int y = recursive(x); // Tainted = {x, y}
    return y; // Tainted = {x, y}
}
