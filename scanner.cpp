#include "include/VirusScanner.hpp"
#include "include/TimeGuard.hpp"
#include <filesystem>
#include <stdexcept>
#include <iostream>

int main(int argc, char* argv[]) {
    TimerGuard timer("Virus scanner execution time: ", std::cout);    

    std::filesystem::path dirPath = "", basePath = "", logPath = "";
    
    size_t inputBufferSize = 16 * 1024 - 100, outputBufferSize = 16 * 1024, threadCount = 0;

    try {
        ParseArgs(argc, argv, dirPath, basePath, logPath, inputBufferSize, outputBufferSize, threadCount);
    } catch (const std::exception& e) {
        std::cerr << "Error parsing arguments: " << e.what() << std::endl;
        std::cerr << "Usage: " << argv[0] << " --base <file> --log <file> --path <directory>" << std::endl;
        return 1;
    }

    try {
        auto[cntFiles, infectedFiles, failedFiles] = ScanDirectory(dirPath, basePath, logPath, inputBufferSize, outputBufferSize, threadCount);
        std::cout << "Total count of scanned files: " << cntFiles << '\n';
        std::cout << "Count of infected files: " << infectedFiles << '\n';
        std::cout << "Count of failed files: " << failedFiles << '\n';
    } catch (const std::exception &e) {
        std::cerr << "ScanDirectory error: " << e.what() << std::endl;
    }

    return 0;
}