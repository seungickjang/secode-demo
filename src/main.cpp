#include <iostream>
#include <cstring> // For strcpy

int main() {
    char buffer[10]; // A buffer designed to hold 9 characters + null terminator
    char input[] = "This is a very long string that will overflow the buffer.";

    // This operation attempts to copy a string larger than 'buffer' can hold,
    // leading to a buffer overflow.
    strcpy(buffer, input); 

    std::cout << "Buffer content: " << buffer << std::endl;

    return 0;
}

/*
#include <iostream>

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
*/