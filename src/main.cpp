#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
  #include <io.h>
  #define access _access
  #define W_OK 2
#else
  #include <unistd.h>
#endif

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::fprintf(stderr, "Usage: %s <name> <path> <list-arg>\n", argv[0]);
        return 1;
    }

    // CWE-120: Buffer overflow (no bounds check)
    char name[16];
    std::strcpy(name, argv[1]); // POTENTIAL OVERFLOW

    // CWE-134: Uncontrolled format string
    std::printf(argv[1]); // USER INPUT AS FORMAT STRING
    std::printf("\n");

    // CWE-367: TOCTOU (time-of-check vs time-of-use)
    const char* path = argv[2];
    if (access(path, W_OK) == 0) {              // check
        FILE* f = std::fopen(path, "w");        // use (race window)
        if (f) {
            std::fputs("test\n", f);
            std::fclose(f);
        }
    }

    // CWE-377: Insecure temporary file creation
    char tmpl[] = "/tmp/myappXXXXXX";
    char* tmp = std::mktemp(tmpl);              // predictable name
    if (tmp) {
        FILE* tf = std::fopen(tmp, "w+");       // race/overwrite risk
        if (tf) {
            std::fputs("temp\n", tf);
            std::fclose(tf);
        }
    }

    // CWE-78: OS command injection
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "ls %s", argv[3]); // unvalidated arg flows to shell
    std::system(cmd);

    std::printf("Hello, %s\n", name); // keep 'name' live
    return 0;
}

/* CWE 119
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
*/

/*
#include <iostream>

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
*/