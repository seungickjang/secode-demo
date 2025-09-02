#include <iostream>
#include <climits>

int main() {
    int a = INT_MAX;   //  2147483647 on most 32-bit int systems
    int b = 1;

    // VULNERABLE: CWE-190 — signed integer overflow (undefined behavior)
    int c = a + b;

    std::cout << "a=" << a << ", b=" << b << ", a+b=" << c << '\n';
    return 0;
}

/*
#include <iostream>

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
*/