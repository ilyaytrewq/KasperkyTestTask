#include <include/VirusScaner.hpp>
#include <filesystem>
#include <stdexcept>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <directory_path> <database_path> <log_path>" << std::endl;
        return 1;
    }

    try {
        ScanDirectory(argv[1], argv[2], argv[3]);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}