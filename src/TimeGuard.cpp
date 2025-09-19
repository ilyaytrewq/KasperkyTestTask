#include "TimeGuard.hpp"

TimerGuard::TimerGuard(std::string message, std::ostream &out) : message(message), out(out)
{
        start_time = std::chrono::steady_clock::now();
}

TimerGuard::~TimerGuard()
{
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        out << message << duration.count() << "\n";
}