#ifndef VirusScaner_hpp
#define VirusScaner_hpp

#include <openssl/evp.h>
#include <vector>
#include <filesystem>
#include <fstream>
#include <string>
#include <tuple>

class MD5Hasher {
    public:
        MD5Hasher();
        ~MD5Hasher();
        void update(const char* data, size_t len);
        void finalize();
        std::vector<unsigned char> getDigest() const;
    
    private:
        EVP_MD_CTX* mdctx;
        unsigned char *digest;
        unsigned int digest_len;
};

class FileScaner {
    public:
        FileScaner(std::ifstream&& istrm, const std::filesystem::path& path, const size_t bufSize = 1024);
        ~FileScaner();
        void calculateFileHash();
        bool isInfected(const std::vector<std::vector<unsigned char>>& virusDatabase);
        std::vector<unsigned char> getFileHash() const;

    private:
        std::filesystem::path filePath;
        std::ifstream inputStream;
        
        char *buffer;
        size_t bufferSize;

        std::vector<unsigned char> fileHash;
        
        char is_infected;
};

class Virus {
    public:
        std::vector<unsigned char> hash;
        std::string name;

        Virus();
        Virus(const std::vector<unsigned char>& hash, const std::string& name);
        ~Virus();
};

class VirusDatabase {
    public:
        VirusDatabase(std::filesystem::path &path);
        ~VirusDatabase();

        void Init();
        std::tuple<bool, std::string> InDatabase(const std::vector<unsigned int> &hash) const;

    private:
        std::filesystem::path dbPath;
        std::vector<Virus> virusDatabase;
        
};

#endif // VirusScaner_hpp