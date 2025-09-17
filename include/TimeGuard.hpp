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
    TimerGuard(std::string message, std::ostream &out) : message(message), out(out)
    {
        start_time = std::chrono::steady_clock::now();
    }

    ~TimerGuard()
    {
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        out <<  message << " time in milliseconds " << duration.count() << "\n";
    }
};

#endif // TIMEGUARD_HPP