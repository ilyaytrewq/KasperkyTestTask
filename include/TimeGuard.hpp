#ifndef TIMEGUARD_HPP
#define TIMEGUARD_HPP

#include <iostream>
#include <chrono>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
  #ifdef VIRUSSCANNER_EXPORTS
    #define VS_API __declspec(dllexport)
  #else
    #define VS_API __declspec(dllimport)
  #endif
#else
  #ifdef VIRUSSCANNER_EXPORTS
    #define VS_API __attribute__((visibility("default")))
  #else
    #define VS_API
  #endif
#endif

class VS_API TimerGuard
{
private:
    std::chrono::steady_clock::time_point start_time;
    std::string message;
    std::ostream &out;

public:
    TimerGuard(std::string message, std::ostream &out);

    ~TimerGuard();
};

#endif // TIMEGUARD_HPP