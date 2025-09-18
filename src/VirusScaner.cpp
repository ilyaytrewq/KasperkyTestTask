#include "../include/VirusScaner.hpp"
#include <stdexcept>
#include <openssl/err.h>

//for debug
#include <iostream>

//##################################
// MD5Hasher implementation
//##################################

MD5Hasher::MD5Hasher() {
    mdctx = EVP_MD_CTX_new();

    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create MD5 context");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize MD5 context");
    }

    digest_len = EVP_MD_size(EVP_md5());
    digest = (unsigned char *)OPENSSL_malloc(digest_len);
    if (digest == nullptr) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to allocate memory for digest");
    }
}

MD5Hasher::~MD5Hasher() {
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(digest);
}

void MD5Hasher::update(const char* data, size_t len) {
    if (1 != EVP_DigestUpdate(mdctx, data, len)) {
        throw std::runtime_error("Failed to update MD5 hash");
    }
}

void MD5Hasher::finalize() {
    if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
        throw std::runtime_error("Failed to finalize MD5 hash");
    }
}

std::vector<unsigned char> MD5Hasher::getDigest() const {
    return std::vector<unsigned char>(digest, digest + digest_len);
}


//##################################
// FileScaner implementation
//##################################

FileScaner::FileScaner(std::ifstream&& istrm, const std::filesystem::path& path, const size_t bufSize) :
    inputStream(std::move(istrm)),
    filePath(path),
    bufferSize(bufSize),
    is_infected(0) {
    buffer = new char[bufSize];
}

FileScaner::~FileScaner() {
    inputStream.close();
    delete [] buffer;
}

void FileScaner::calculateFileHash() {
    MD5Hasher hasher = MD5Hasher();
    int readBytes = 0;
    
    do {
        inputStream.read(buffer, bufferSize);
        readBytes = inputStream.gcount();

        try {
            hasher.update(buffer, readBytes); //add ErrorHandler
        } catch (std::exception &e) {
            throw e;
        }

    } while (readBytes == bufferSize);

    try {
        hasher.finalize();
    } catch (std::exception &e) {
        throw e;
    }

    fileHash = hasher.getDigest();
};

bool FileScaner::isInfected(const std::vector<std::vector<unsigned char>>& virusDatabase) {
    if (0 != is_infected){
        return (is_infected == 1 ? true : false);
    }

    for (const auto &virus : virusDatabase) {
        if (virus == fileHash){
            is_infected = 1;
            return true;
        }
    }
    is_infected = -1;
    return false;
}

std::vector<unsigned char> FileScaner::getFileHash() const {
    return fileHash;
}

std::string FileScaner::getFileHashString() const {
    static const char hexDigits[] = "0123456789abcdef";
    std::string hash = "";
    for (auto digit : this->getFileHash()) {
        hash.push_back(hexDigits[digit >> 4]);
        hash.push_back(hexDigits[digit & 0x0F]);
    }
}


//###############################
// Virus implementation
//###############################


Virus::Virus(const std::vector<unsigned char>& hash, const std::string& name) : hash(hash), name(name) {}
Virus::~Virus() {}


//#################################
// VirusDatabase implementation
//#################################

VirusDatabase::VirusDatabase(const std::filesystem::path &path) : basePath(path) {}
VirusDatabase::~VirusDatabase() {}

void VirusDatabase::Init() {
    std::ifstream dbFile(basePath, std::ios::in);
    if (!dbFile.is_open()) {
        throw std::runtime_error("Failed to open virus database file");
    }

    int numStirngs = 1;
    std::string inputString;
    while (std::getline(dbFile, inputString)) {
        Virus virus;
        size_t delimiterPos = inputString.find(';');
        
        if (delimiterPos == std::string::npos) {
            //log error numString
            continue; 
        }
        
        virus.name = inputString.substr(delimiterPos + 1);
        std::string hashStr = inputString.substr(0, delimiterPos);
        
        if (hashStr.size() != 32) {
            //log error numString
            continue; 
        }

        for (size_t i = 0; i < 32; i += 2) {
            std::string byteString = hashStr.substr(i, 2);
            virus.hash.push_back(static_cast<unsigned char>(std::stoul(byteString, nullptr, 16)));
        }

        virusDatabase.push_back(virus);
        numStirngs++;
    }

    dbFile.close();
}

std::tuple<bool, std::string> VirusDatabase::InDatabase(const std::vector<unsigned char> &hash) const {
    for (const auto &virus : virusDatabase) {
        if (virus.hash == hash) {
            return std::make_tuple(true, virus.name);
        }
    }
    return std::make_tuple(false, "");
}


//#################################
// ScanDirectory implementation
//#################################

void ScanDirectory(const std::filesystem::path& dirPath, const std::filesystem::path& basePath, const std::filesystem::path& logPath) {
    if (!std::filesystem::exists(dirPath) || !std::filesystem::is_directory(dirPath)) {
        throw std::runtime_error("Invalid directory path");
    }
    if (!std::filesystem::exists(basePath) || !std::filesystem::is_regular_file(basePath)) {
        throw std::runtime_error("Invalid database file path");
    }
    if (!std::filesystem::exists(logPath) || !std::filesystem::is_regular_file(logPath)) {
        throw std::runtime_error("Invalid log file path"); 
    }

    unsigned int cntFiles = 0, infectedFiles = 0, failesFiles = 0;

    std::ofstream logOut(logPath, std::ios::out);

    VirusDatabase virusDB(basePath);
    virusDB.Init(); 

    for (auto const &dir_entry : std::filesystem::recursive_directory_iterator(dirPath)) {
        if (dir_entry.is_regular_file()) {
            cntFiles++;

            std::ifstream fileStream(dir_entry.path(), std::ios::in | std::ios::binary);
            if (!fileStream.is_open()) {
                logOut << "ScanDirectory error: Failed to open file: " << dir_entry.path().string() << '\n';
                failesFiles++;
                continue;
            }

            FileScaner fileScaner(std::move(fileStream), dir_entry.path());
            try {
                fileScaner.calculateFileHash();
            } catch (const std::exception &e) {
                // Log error calculating hash
                logOut << "CalculateFileHash error: " << e.what() << '\n';
                continue;
            }

            auto [isInfected, virusName] = virusDB.InDatabase(fileScaner.getFileHash());
            if (isInfected) {
                infectedFiles++;
                // Log infection details to logPath
                std::cout << "Infected file: " << dir_entry.path() << " Virus: " << virusName << std::endl;
                logOut << "File: " << dir_entry.path().string() << " hash: " << fileScaner.getFileHashString() << " verdict: infected\n";
            } else {
                // Log clean file details to logPath
                std::cout << "Clean file: " << dir_entry.path() << std::endl;
                logOut << "File: " << dir_entry.path().string() << " hash: " << fileScaner.getFileHashString() << " verdict: infected\n";
            }
        }
    }

}