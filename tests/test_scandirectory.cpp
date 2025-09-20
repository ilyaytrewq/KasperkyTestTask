#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include "VirusScanner.hpp"


TEST(ScanDirectoryTest, DetectsInfectedFile) {
    auto tmpdir = std::filesystem::temp_directory_path() / ("vs_scan_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(tmpdir);


    std::filesystem::path f1 = tmpdir / "infected.txt";
    std::ofstream(f1, std::ios::binary) << "hello";


    std::filesystem::path f2 = tmpdir / "clean.txt";
    std::ofstream(f2, std::ios::binary) << "clean content";


    std::filesystem::path db = tmpdir / "base.csv";
    std::ofstream ofs(db);
    ofs << "5d41402abc4b2a76b9719d911017c592;FakeVirus\n";
    ofs.close();


    std::filesystem::path log = tmpdir / "report.log";
    std::ofstream(log).close();


    auto [total, infected, failed] = ScanDirectory(tmpdir, db, log, 1024, 4096, 1);

    EXPECT_EQ(total, 4u);
    EXPECT_EQ(infected, 1u);
    EXPECT_EQ(failed, 0u);


    std::filesystem::remove_all(tmpdir);
}