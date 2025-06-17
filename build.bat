@echo off
REM Build CS2AntiCheat.exe via CMake and Visual Studio 2022 x64
if not exist build mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
copy "Release\CS2AntiCheat.exe" "..\CS2AntiCheat.exe"
echo Build complete: CS2AntiCheat.exe created in project root.
pause

