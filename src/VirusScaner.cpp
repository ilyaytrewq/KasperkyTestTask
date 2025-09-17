#include "../include/VirusScaner.hpp"
#include <stdexcept>
#include <openssl/err.h>

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
        hasher.update(buffer, readBytes); //add ErrorHandler
    } while (readBytes == bufferSize);

    hasher.finalize();//ErrorHandler
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