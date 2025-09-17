#include "../include/VirusScaner.hpp"
#include <stdexcept>
#include <openssl/err.h>

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

void MD5Hasher::update(const unsigned char* data, size_t len) {
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



