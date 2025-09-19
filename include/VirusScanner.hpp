#ifndef VirusScanner_hpp
#define VirusScanner_hpp

#include <openssl/evp.h>
#include <vector>
#include <filesystem>
#include <fstream>
#include <string>
#include <tuple>

class MD5Hasher {
    public:
        MD5Hasher();
        ~MD5Hasher() = default;
        void update(const char* data, size_t len);
        void finalize();
        std::vector<unsigned char> getDigest() const;
    
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
        FileScanner(std::ifstream&& istrm, const std::filesystem::path& path, const size_t bufSize = 1024);
        ~FileScanner();
        void calculateFileHash();
        bool isInfected(const std::vector<std::vector<unsigned char>>& virusDatabase);
        std::vector<unsigned char> getFileHash() const;
        std::string getFileHashString() const;

    private:
        std::ifstream inputStream;
        std::filesystem::path filePath;
        
        std::unique_ptr<char[]> buffer;
        size_t bufferSize;

        std::vector<unsigned char> fileHash;
        
        char is_infected;
};

class Virus {
    public:
        std::vector<unsigned char> hash;
        std::string name;

        Virus() = default;
        Virus(const std::vector<unsigned char>& hash, const std::string& name);
        ~Virus() = default;
};

class VirusDatabase {
    public:
        VirusDatabase(const std::filesystem::path &path);
        ~VirusDatabase() = default;

        void Init(std::ofstream &logOut);
        std::tuple<bool, std::string> InDatabase(const std::vector<unsigned char> &hash) const;

    private:
        std::filesystem::path basePath;
        std::vector<Virus> virusDatabase;
        
};


std::tuple<unsigned int, unsigned int, unsigned int>  ScanDirectory(const std::filesystem::path& dirPath, const std::filesystem::path &basePath, const std::filesystem::path &logPath); 

#endif // VirusScanner_hpp