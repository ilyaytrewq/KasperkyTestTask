#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <chrono>
#include <thread>
#include "VirusScanner.hpp"

TEST(FileScannerMD5Test, KnownContent) {
    using namespace std::filesystem;
    auto tmpdir = temp_directory_path() / ("vs_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    create_directories(tmpdir);

    path f = tmpdir / "hello.txt";
    {
        std::ofstream ofs(f, std::ios::binary);
        ofs << "hello";
        ofs.close(); 
    }

    std::string hash;
    {
        std::ifstream ifs(f, std::ios::binary);
        FileScanner scanner(std::move(ifs), f, 1024);
        scanner.calculateFileHash();
        hash = scanner.getFileHashString();
    }

    EXPECT_EQ(hash, "5d41402abc4b2a76b9719d911017c592"); // md5("hello")

    std::error_code ec;
    for (int i = 0; i < 5; ++i) {
        ec.clear();
        remove_all(tmpdir, ec);
        if (!ec) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
}