#ifndef TIMEGUARD_HPP
#define TIMEGUARD_HPP

#include <iostream>
#include <chrono>
#include <string>

class TimerGuard
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