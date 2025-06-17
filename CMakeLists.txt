cmake_minimum_required(VERSION 3.15)
project(CS2AntiCheat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC OFF)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt6_wrap_ui(UIS rc_mainwindow ui/mainwindow.ui)
qt6_add_resources(RCS resources.qrc)

add_executable(${PROJECT_NAME}
    ${UIS}
    ${RCS}
    src/main.cpp
    src/mainwindow.cpp
    src/processscanner.cpp
    src/filescanner.cpp
    src/memoryscanner.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Widgets)

