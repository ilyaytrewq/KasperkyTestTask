#include <gtest/gtest.h>
#include <filesystem>
#include "../include/VirusScanner.hpp"

TEST(ParseArgsTest, MissingRequiredArgumentThrows) {
    std::filesystem::path dir, base, log;
    size_t ibuf = 0, obuf = 0, threads = 0;


    const char* argv_const[] = {"scanner", "--base", "base.csv", "--log", "report.log"};
    int argc = sizeof(argv_const)/sizeof(argv_const[0]);
    char** argv = const_cast<char**>(argv_const);

    EXPECT_THROW(ParseArgs(argc, argv, dir, base, log, ibuf, obuf, threads), std::invalid_argument);
}


TEST(ParseArgsTest, ParsesRequiredArgs) {
    std::filesystem::path dir, base, log;
    size_t ibuf = 0, obuf = 0, threads = 0;


    const char* argv_const[] = {
        "scanner",
        "--base", "base.csv",
        "--log", "report.log",
        "--path", "scan_dir",
        "--ibuf", "1024",
        "--obuf", "2048",
        "--threads", "2"
    };
    int argc = sizeof(argv_const)/sizeof(argv_const[0]);
    char** argv = const_cast<char**>(argv_const);


    EXPECT_NO_THROW(ParseArgs(argc, argv, dir, base, log, ibuf, obuf, threads));


    EXPECT_EQ(base, "base.csv");
    EXPECT_EQ(log, "report.log");
    EXPECT_EQ(dir, "scan_dir");
    EXPECT_EQ(ibuf, 1024u);
    EXPECT_EQ(obuf, 2048u);
    EXPECT_EQ(threads, 2u);
}
