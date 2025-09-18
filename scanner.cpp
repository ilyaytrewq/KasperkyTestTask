#include "include/VirusScaner.hpp"
#include "include/TimeGuard.hpp"
#include <filesystem>
#include <stdexcept>
#include <iostream>
#include <getopt.h>

#include <stdio.h>

void parseArgs(int argc, char *argv[], std::filesystem::path &dirPath, std::filesystem::path &basePath, std::filesystem::path &logPath) {
    const char * shortOptions = "b:l:p:";

    const struct option longOptions[] = {
        { "base", required_argument, 0, 'b' },
        { "log", required_argument, 0, 'l' },
        { "path", required_argument, 0, 'p' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, shortOptions, longOptions, NULL)) != -1) {
        switch (opt)
        {
        case 'b':
            basePath = optarg;
            break;
        case 'l':
            logPath = optarg;
            break;
        case 'p':
            dirPath = optarg;
            break;
        case '?':
            throw std::runtime_error("Unknown option");
        default:
            break;
        }
    }    

    if (dirPath.empty()) {
        throw std::invalid_argument("Missing required argument: --path");
    }

    if (basePath.empty()) {
        throw std::invalid_argument("Missing required argument: --base");
    }

    if(logPath.empty()) {
        throw std::invalid_argument("Missing required argument: --log");
    }

}

int main(int argc, char* argv[]) {
    TimerGuard timer("Virus scanner", std::cout);    

    for (int i = 0; i < argc; ++i) {
        std::cout << argv[i] << std::endl;
    }

    std::filesystem::path dirPath = "", basePath = "", logPath = "";
    try {
        parseArgs(argc, argv, dirPath, basePath, logPath);
    } catch (const std::exception& e) {
        std::cerr << "Error parsing arguments: " << e.what() << std::endl;
        std::cerr << "Usage: " << argv[0] << " --base <file> --log <file> --path <directory>" << std::endl;
        return 1;
    }
   

    try {
        ScanDirectory(dirPath, basePath, logPath);
    } catch (const std::exception &e) {
        
    }

    return 0;
}