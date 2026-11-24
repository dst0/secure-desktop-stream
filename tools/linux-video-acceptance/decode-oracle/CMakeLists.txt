cmake_minimum_required(VERSION 3.22)
project(sds_decode_oracle LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
find_package(Qt6 REQUIRED COMPONENTS Core Network Gui)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
set(PKG_CONFIG_ARGN --define-variable=prefix=/ffmpeg)
set(ENV{PKG_CONFIG_PATH} /ffmpeg/lib/pkgconfig)
pkg_check_modules(FFMPEG REQUIRED IMPORTED_TARGET libavcodec libavutil libswscale)
add_subdirectory(/source/moonlight-common-c/moonlight-common-c protocol)
set(BACKEND /source/app/backend)
add_executable(sds-decode-oracle main.cpp
    ${BACKEND}/identitymanager.cpp ${BACKEND}/nvpairingmanager.cpp
    ${BACKEND}/nvhttp.cpp ${BACKEND}/nvhttp.h ${BACKEND}/nvcomputer.cpp
    ${BACKEND}/nvaddress.cpp ${BACKEND}/nvapp.cpp
    ${BACKEND}/certpinning.cpp ${BACKEND}/lanpolicy.cpp)
target_include_directories(sds-decode-oracle PRIVATE /source/app
    /source/moonlight-common-c/moonlight-common-c/src)
target_link_libraries(sds-decode-oracle PRIVATE moonlight-common-c
    Qt6::Core Qt6::Network Qt6::Gui OpenSSL::Crypto PkgConfig::FFMPEG)
