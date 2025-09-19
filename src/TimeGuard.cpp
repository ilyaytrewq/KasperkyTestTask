#include "TimeGuard.hpp"

TimerGuard::TimerGuard(std::string message, std::ostream &out) : message(message), out(out)
{
        start_time = std::chrono::steady_clock::now();
}

TimerGuard::~TimerGuard()
{
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        auto seconds = ms / 1000;
        auto milliseconds = ms % 1000;
        
        out << message << seconds << "s " << milliseconds << "ms\n";
}