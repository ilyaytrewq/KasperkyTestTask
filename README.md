# KasperkyTestTask

# VirusScanner

**VirusScanner** — консольная утилита для рекурсивного сканирования директорий по MD5‑хешам файлов.  
Для каждого файла вычисляется MD5 потоковым способом (блоками, без загрузки всего файла в память) и сравнивается с базой известных вредоносных хэшей. Результаты записываются в лог‑файл, а в консоль выводится итоговый отчёт (количество обработанных, найденных и неудачных файлов, время выполнения).

---

## Возможности

- Рекурсивное сканирование директорий.
- Потоковое чтение файлов (поддержка больших файлов).
- Сравнение MD5 с базой в формате `"<md5>;<Name>"`.
- Логирование: путь файла, MD5 в hex, вердикт (infected/clean) и при обнаружении — имя угрозы.
- Итоговая статистика и время выполнения.
- Сборка через CMake и использование OpenSSL (libcrypto) для вычисления MD5.

---

## Требования

- C++20
- CMake ≥ 3.19
- OpenSSL (dev headers). Примеры пакетов:
  - Debian/Ubuntu: `libssl-dev`
  - Fedora: `openssl-devel`
- Компилятор: `g++` или `clang++`

---

## Сборка

1. Клонируйте репозиторий и перейдите в корень проекта:
```bash
git clone https://github.com/ilyaytrewq/KasperkyTestTask.git
cd KasperkyTestTask
```

2. Создайте каталог сборки и соберите проект:
```bash
cmake -S . -B build
cmake --build build/
```

После сборки бинарник будет находиться в `build/bin/scanner` (на Windows — `scanner.exe`).

Если CMake не находит OpenSSL, установите пакет и повторите команду `cmake --build build/`:
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install build-essential cmake libssl-dev
```

---

## Запуск

Синтаксис:
```
scanner --base <path_to_base_csv> --log <path_to_log_file> --path <directory_to_scan>
```

Примеры:

Linux / macOS:
```bash
./build/bin/scanner --base /home/user/data/KasperskyTestTask/base.csv --log /home/user/data/KasperskyTestTask/report.log --path /home/user/scan_folder
```

Windows (cmd / PowerShell):
```
.\build\bin\scanner.exe --base C:\data\base.csv --log C:\data\report.log --path C:\data\scan_folder
```

**Примечание:** если лог‑файл не существует, программа попытается его создать (при наличии прав). Для дозаписи в конец лог‑файла используется режим `append` в коде (`std::ofstream(logPath, std::ios::out | std::ios::app)`).

---

## Формат базы (CSV)

Файл базы — текстовый файл, каждая строка в формате:
```
<md5_hash>;<VerdictName>
```

Пример:
```
a9963513d093ffb2bc7ceb9807771ad4;Exploit
ac6204ffeb36d2320e52f1d551cfa370;Dropper
8ee70903f43b227eeb971262268af5a8;Downloader
```

Требования:
- MD5 в нижнем регистре, 32 шестнадцатеричных символа;
- Строки разделяются символом `;`;
- Неверно сформатированные строки логируются и пропускаются.

---

## Пример вывода

**Консоль:**
```
Total count of scanned files: 196
Count of infected files: 2
Count of failed files: 1
Virus scanner execution time: 180
```

**Пример строки в логе:**
```
File: /home/user/scan_folder/example.exe hash: a9963513d093ffb2bc7ceb9807771ad4 verdict: infected (Exploit)
```


---

## Полезные команды

Проверить MD5 файла (Linux/macOS):
```bash
md5sum path/to/file
```

Перестроить проект с чисткой:
```bash
cmake --build build --clean-first
```

---

## Структура репозитория (рекомендуется)
```
.
├─ CMakeLists.txt
├─ README.md
├─ scanner.cpp
├─ include/
│  ├─ VirusScanner.hpp
│  └─ TimeGuard.hpp
├─ src/
│  ├─ VirusScaner.cpp
│  └─ TimeGuard.cpp
├─ base.csv
├─ build/                  
├─ tests/        
│  ├─ test_filescanner_md5.cpp
│  ├─ test_parser.cpp
|  ├─ test_scandirectory.cpp
|  └─ test_virusdb.cpp
```


Если хочешь — могу:
- создать `README.md` в корне репозитория прямо сейчас,
- добавить пример `base.csv` в `data/`,
- подготовить `CMakeLists.txt` для включения тестов,
- или реализовать базовую многопоточную версию сканирования.