#include "include/VirusScanner.hpp"
#include "include/TimeGuard.hpp"
#include <filesystem>
#include <stdexcept>
#include <iostream>
#include <getopt.h>

#include <stdio.h>

void parseArgs(int argc, char *argv[], std::filesystem::path &dirPath, std::filesystem::path &basePath, std::filesystem::path &logPath, size_t &inputBufferSize, size_t &outputBufferSize, size_t &threadCount) {
    const char * shortOptions = "b:l:p:i:o:t:";

    const struct option longOptions[] = {
        { "base", required_argument, 0, 'b' },
        { "log", required_argument, 0, 'l' },
        { "path", required_argument, 0, 'p' },
        { "ibuf", required_argument, 0, 'i' },
        { "obuf", required_argument, 0, 'o' },
        { "threads", required_argument, 0, 't' },
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
        case 'i':
            if (optarg)
                inputBufferSize = std::stoul(optarg); 
            break;
        case 'o':
            if (optarg)
                outputBufferSize = std::stoul(optarg);
            break;
        case 't':
            if (optarg)
                threadCount = std::stoul(optarg);
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
    TimerGuard timer("Virus scanner execution time: ", std::cout);    

    std::filesystem::path dirPath = "/home/ilyaytrewq/Documents/", basePath = "/home/ilyaytrewq/Documents/projects/KasperkyTestTask/base.csv", logPath = "/home/ilyaytrewq/Documents/projects/KasperkyTestTask/report.log";
    
    size_t inputBufferSize = 16 * 1024 - 100, outputBufferSize = 16 * 1024, threadCount = 0;

    try {
        parseArgs(argc, argv, dirPath, basePath, logPath, inputBufferSize, outputBufferSize, threadCount);
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