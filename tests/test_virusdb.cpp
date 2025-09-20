#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <chrono>
#include "VirusScanner.hpp"

TEST(VirusDatabaseTest, InitAndLookup) {
    auto tmpdir = std::filesystem::temp_directory_path() / ("vs_db_" + std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    ASSERT_TRUE(std::filesystem::create_directories(tmpdir));

    std::filesystem::path db = tmpdir / "base.csv";
    {
        std::ofstream ofs(db);
        ASSERT_TRUE(ofs.is_open());
        ofs << "5d41402abc4b2a76b9719d911017c592;TestVirus\n";
    }

    std::filesystem::path log = tmpdir / "report.log";
    {
        std::ofstream ofs(log);
        ASSERT_TRUE(ofs.is_open());
    }

    {
        std::ofstream logOut(log, std::ios::app);
        ASSERT_TRUE(logOut.is_open());
        VirusDatabase vdb(db);
        EXPECT_NO_THROW(vdb.Init(logOut));

        auto [found, name] = vdb.InDatabase("5d41402abc4b2a76b9719d911017c592");
        EXPECT_TRUE(found);
        EXPECT_EQ(name, "TestVirus");
    }

    std::error_code ec;
    std::filesystem::remove_all(tmpdir, ec);
    if (ec) {
        std::cerr << "Warning: failed to remove tmpdir: " << ec.message() << "\n";
    }
}
