# CS2 Anti-Cheat

This project provides a simple Qt-based Windows application that scans for known Counter-Strike 2 cheats. The application checks running processes, files on local drives and searches memory of the game process for cheat patterns.

## Build

Windows build requires Qt 6 and CMake 3.15 or newer. Use the provided `build.bat` script to generate Visual Studio files and compile the release build:

```bat
build.bat
```

`CS2AntiCheat.exe` will be copied to the project root on success.

