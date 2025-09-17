#ifndef VirusScaner_hpp
#define VirusScaner_hpp

#include <openssl/evp.h>
#include <vector>
#include <filesystem>

class MD5Hasher {
    public:
        MD5Hasher();
        ~MD5Hasher();
        void update(const unsigned char* data, size_t len);
        void finalize();
        std::vector<unsigned char> getDigest() const;
    
    private:
        EVP_MD_CTX* mdctx;
        unsigned char *digest;
        unsigned int digest_len;
};

class FileScaner {
    public:
        FileScaner();
        ~FileScaner();
        
    
    private:
        MD5Hasher hasher;
        std::filesystem::path filePath;

};

#endif // VirusScaner_hpp