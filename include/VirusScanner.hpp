#ifndef VirusScanner_hpp
#define VirusScanner_hpp

#include <openssl/evp.h>
#include <vector>
#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <tuple>
#include <unordered_map>

class MD5Hasher {
    public:
        MD5Hasher();
        ~MD5Hasher() = default;
        void update(const char* data, size_t len);
        void finalize();
        std::array<unsigned char, 16> getDigest() const;
    
    private:

        struct EVP_MD_CTX_Deleter {
            void operator()(EVP_MD_CTX *ctx) const {
                EVP_MD_CTX_free(ctx);
            }
        };

        struct OPENSSL_Deleter {
            void operator()(unsigned char* ptr) const {
                OPENSSL_free(ptr);
            }
        };

        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> mdctx;
        std::unique_ptr<unsigned char, OPENSSL_Deleter> digest;
        unsigned int digest_len;
};

class FileScanner {
    public:
        FileScanner(std::ifstream&& istrm, const std::filesystem::path& path, const size_t bufSize);
        ~FileScanner();
        void calculateFileHash();
        std::array<unsigned char, 16> getFileHash() const;
        std::string getFileHashString() const;

    private:
        std::ifstream inputStream;
        std::filesystem::path filePath;
        
        std::unique_ptr<char[]> buffer;
        size_t bufferSize;

        std::array<unsigned char, 16> fileHash;
        
        char is_infected;
};

class VirusDatabase {
    public:
        VirusDatabase(const std::filesystem::path &path);
        ~VirusDatabase() = default;

        void Init(std::ofstream &logOut);
        std::tuple<bool, std::string> InDatabase(const std::string &hash) const;

    private:
        std::filesystem::path basePath;
        std::unordered_map<std::string, std::string> virusDatabase;
        
};

std::tuple<unsigned int, unsigned int, unsigned int>  ScanDirectory(const std::filesystem::path& dirPath, const std::filesystem::path &basePath, const std::filesystem::path &logPath, size_t bufferSize = 8092, unsigned int countThreads = 0); 

#endif // VirusScanner_hpp
