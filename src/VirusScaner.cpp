#include "VirusScanner.hpp"
#include <stdexcept>
#include <openssl/err.h>
#include <atomic>
#include <thread>
#include <iostream>
#include <algorithm>
#include <getopt.h>
#include <mutex>

//##################################
// MD5Hasher implementation
//##################################

MD5Hasher::MD5Hasher() {
    mdctx.reset(EVP_MD_CTX_new());
    if (!mdctx) {
        throw std::runtime_error("Failed to create MD5 context");
    }

    if (1 != EVP_DigestInit_ex(mdctx.get(), EVP_md5(), nullptr)) {
        throw std::runtime_error("Failed to initialize MD5 context");
    }

    digest_len = EVP_MD_size(EVP_md5());
    if (digest_len <= 0) {
        throw std::runtime_error("Failed to get MD5 digest size");
    }

    digest.reset(static_cast<unsigned char *>(OPENSSL_malloc(digest_len)));
    if (!digest) {
        throw std::runtime_error("Failed to allocate memory for digest");
    }
}


void MD5Hasher::update(const char* data, size_t len) {
    if (1 != EVP_DigestUpdate(mdctx.get(), data, len)) {
        throw std::runtime_error("Failed to update MD5 hash");
    }
}

void MD5Hasher::finalize() {
    if (1 != EVP_DigestFinal_ex(mdctx.get(), digest.get(), &digest_len)) {
        throw std::runtime_error("Failed to finalize MD5 hash");
    }
}

std::array<unsigned char, 16> MD5Hasher::getDigest() const {
    std::array<unsigned char, 16> result;
    std::copy(digest.get(), digest.get() + digest_len, result.begin());
    return result;
}


//##################################
// FileScanner implementation
//##################################

FileScanner::FileScanner(std::ifstream&& istrm, const std::filesystem::path& path, const size_t bufSize) :
    inputStream(std::move(istrm)),
    filePath(path),
    bufferSize(bufSize),
    is_infected(0) {
    buffer = std::make_unique<char[]>(bufferSize);
}

FileScanner::~FileScanner() {
    inputStream.close();
}

void FileScanner::calculateFileHash() {
    MD5Hasher hasher = MD5Hasher();
    std::streamsize readBytes = 0;
    
    do {
        inputStream.read(buffer.get(), bufferSize);
        readBytes = inputStream.gcount();

        try {
            hasher.update(buffer.get(), readBytes); 
        } catch (std::exception &e) {
            throw e;
        }

    } while ((size_t)readBytes == bufferSize);

    try {
        hasher.finalize();
    } catch (std::exception &e) {
        throw e;
    }

    fileHash = hasher.getDigest();
};

std::array<unsigned char, 16> FileScanner::getFileHash() const {
    return fileHash;
}

std::string FileScanner::getFileHashString() const {
    static const char hexDigits[] = "0123456789abcdef";
    std::string hash = "";
    for (auto digit : this->getFileHash()) {
        hash.push_back(hexDigits[digit >> 4]);
        hash.push_back(hexDigits[digit & 0x0F]);
    }
    return hash;
}


//#################################
// VirusDatabase implementation
//#################################

VirusDatabase::VirusDatabase(const std::filesystem::path &path) : basePath(path) {}

void VirusDatabase::Init(std::ofstream &logOut) {
    std::ifstream dbFile(basePath, std::ios::in);
    if (!dbFile.is_open()) {
        throw std::runtime_error("Init VirusDatabase error: failed to open virus database file: " + basePath.string());
    }

    int rowNum = 1;
    std::string inputString;
    while (std::getline(dbFile, inputString)) {
        size_t delimiterPos = inputString.find(';');
        
        if (delimiterPos == std::string::npos) {
            logOut << "Init VirusDatabase warning: incorrect row(" << rowNum << ") in file";
            continue; 
        }
        
        std::string virusName = inputString.substr(delimiterPos + 1);
        std::string hashStr = inputString.substr(0, delimiterPos);
        
        if (hashStr.size() != 32) {
            logOut << "Init VirusDatabase warning: incorrect hash=" << hashStr << "in row(" << rowNum << ") in file";
            continue; 
        }

        virusDatabase[hashStr] = virusName;
        rowNum++;
    }

    dbFile.close();
}

std::tuple<bool, std::string> VirusDatabase::InDatabase(const std::string &hash) const {
    auto it = virusDatabase.find(hash);
    if (it != virusDatabase.end()) {
        return std::make_tuple(true, it->second);
    }
    return std::make_tuple(false, "");
}



//#################################
// Logger implementation
//#################################

Logger::Logger(std::ofstream& ostrm, std::mutex &sharedMutex, size_t bufferSize, int countRows) : logOut(ostrm), fileMutex(sharedMutex), count(0), countRows(countRows) {
    buffer.reserve(bufferSize);
}

Logger::~Logger() {
    try {
        printBuffer();
    } catch(...) {
        std::cerr << "printBuffer exception\n" << std::endl;
    }
}

void Logger::logString(const std::string &s) {
    buffer += s;
    count++;
    if (buffer.size() >= bufferSize || count >= countRows) {
        printBuffer();
    }
}

void Logger::printBuffer() {
    count = 0;
    if (buffer.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lk(fileMutex);
    logOut << buffer;
    buffer.clear();
}


//#################################
// ParseArgs implementation
//#################################


void ParseArgs(int argc, char *argv[], std::filesystem::path &dirPath, std::filesystem::path &basePath, std::filesystem::path &logPath, size_t &inputBufferSize, size_t &outputBufferSize, size_t &threadCount) 
{
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        // --key=value
        auto eq = arg.find('=');
        if (arg.rfind("--", 0) == 0 && eq != std::string::npos) {
            std::string key = arg.substr(2, eq - 2);
            std::string val = arg.substr(eq + 1);

            if (key == "base") basePath = val;
            else if (key == "log") logPath = val;
            else if (key == "path") dirPath = val;
            else if (key == "ibuf") inputBufferSize = std::stoull(val);
            else if (key == "obuf") outputBufferSize = std::stoull(val);
            else if (key == "threads") threadCount = std::stoull(val);
            else throw std::runtime_error("Unknown option: --" + key);
            continue;
        }

        // long option --key value
        if (arg.rfind("--", 0) == 0) {
            std::string key = arg.substr(2);
            std::string val;
            if (i + 1 < argc) {
                val = argv[++i];
            } else {
                throw std::runtime_error("Missing value for option: --" + key);
            }

            if (key == "base") basePath = val;
            else if (key == "log") logPath = val;
            else if (key == "path") dirPath = val;
            else if (key == "ibuf") inputBufferSize = std::stoull(val);
            else if (key == "obuf") outputBufferSize = std::stoull(val);
            else if (key == "threads") threadCount = std::stoull(val);
            else throw std::runtime_error("Unknown option: --" + key);
            continue;
        }

        // short options: -i1024 or -i 1024
        if (arg.rfind("-", 0) == 0 && arg.size() >= 2) {
            char opt = arg[1];
            std::string val;
            if (arg.size() > 2) {
                val = arg.substr(2);
            } else {
                if (i + 1 < argc) {
                    val = argv[++i];
                } else {
                    throw std::runtime_error(std::string("Missing value for option: -") + opt);
                }
            }

            switch (opt) {
                case 'b': basePath = val; break;
                case 'l': logPath = val; break;
                case 'p': dirPath = val; break;
                case 'i': inputBufferSize = std::stoull(val); break;
                case 'o': outputBufferSize = std::stoull(val); break;
                case 't': threadCount = static_cast<size_t>(std::stoull(val)); break;
                default:
                    throw std::runtime_error(std::string("Unknown short option: -") + opt);
            }
            continue;
        }

        throw std::runtime_error("Unknown argument: " + arg);
    }

    if (dirPath.empty()) {
        throw std::invalid_argument("Missing required argument: --path");
    }
    if (basePath.empty()) {
        throw std::invalid_argument("Missing required argument: --base");
    }
    if (logPath.empty()) {
        throw std::invalid_argument("Missing required argument: --log");
    }
}

//#################################
// ScanDirectory implementation
//#################################

std::tuple<unsigned int, unsigned int, unsigned int> ScanDirectory(
    const std::filesystem::path& dirPath, 
    const std::filesystem::path& basePath, 
    const std::filesystem::path& logPath,
    size_t inputBufferSize,
    size_t outputBufferSize,
    unsigned int countThreads) 
{
    
    if (!std::filesystem::exists(dirPath) || !std::filesystem::is_directory(dirPath)) {
        throw std::runtime_error("Invalid directory path");
    }
    if (!std::filesystem::exists(basePath) || !std::filesystem::is_regular_file(basePath)) {
        throw std::runtime_error("Invalid database file path");
    }
    if (!std::filesystem::exists(logPath) || !std::filesystem::is_regular_file(logPath)) {
        throw std::runtime_error("Invalid log file path"); 
    }

    std::ofstream logOut(logPath, std::ios::app);

    VirusDatabase virusDB(basePath);
    try {
        virusDB.Init(logOut); 
    } catch (const std::exception &e) {
        logOut << "Init VirusDatabase error: " << e.what() << std::endl;
        throw std::runtime_error("ScanDirectory error: failed initializate VirusDatabase");
    }
     

    std::vector<std::filesystem::path> filePaths;
    for (auto const &dir_entry : std::filesystem::recursive_directory_iterator(dirPath)) {
        if (dir_entry.is_regular_file()) {
            filePaths.push_back(dir_entry.path());
        }
    }
    unsigned int countFiles = filePaths.size();
    std::atomic<unsigned int> infectedFiles{0};
    std::atomic<unsigned int> failedFiles{0};
    std::mutex logMutex;

    if(countThreads == 0){
        countThreads = std::max(std::thread::hardware_concurrency(), 4u);
        countThreads = std::min(countThreads, countFiles);
    }

    std::vector<std::thread> workers;
    std::atomic<size_t> nextIndex{0};
    auto worker = [&]() {
        Logger logger(logOut, logMutex, outputBufferSize);
        for (;;) {
            size_t idx = nextIndex.fetch_add(1, std::memory_order_relaxed);
            if (idx >= filePaths.size()) {
                break;
            }

            const auto &filePath = filePaths[idx];

            std::ifstream fileStream(filePath, std::ios::in | std::ios::binary);
            if (!fileStream.is_open()) {
                failedFiles.fetch_add(1, std::memory_order_relaxed);
                logger.logString("ScanDirectory warning: Failed to open file: " + filePath.string() + '\n');
                continue;
            }
            
            try {
                FileScanner fileScanner(std::move(fileStream), filePath, inputBufferSize);

                fileScanner.calculateFileHash();

                std::string fileHash = fileScanner.getFileHashString();

                auto [isInfected, virusName] = virusDB.InDatabase(fileHash);
                if (isInfected) {
                    infectedFiles.fetch_add(1, std::memory_order_relaxed);
                    logger.logString("File: " + filePath.string() + " hash: " + fileHash + " verdict: infected(" + virusName + ")\n");
                } else {
                    logger.logString("File: " + filePath.string() + " hash: " + fileHash + " verdict: clean\n");
                }
            } catch (const std::exception &e) {
                failedFiles.fetch_add(1, std::memory_order_relaxed);
                logger.logString("CalculateFileHash error for file " + filePath.string() + ": " + e.what() + '\n');
            } catch (...) {
                failedFiles.fetch_add(1, std::memory_order_relaxed);
                logger.logString("Unknown error while processing file " + filePath.string() + '\n');
            }
        }
    }; 

    workers.reserve(countThreads);
    for (unsigned int i = 0; i < countThreads; ++i) {
        workers.emplace_back(worker);
    }

    for (auto &t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }


    logOut << std::endl;
    logOut.close();

    return std::make_tuple(countFiles, infectedFiles.load(), failedFiles.load());
}