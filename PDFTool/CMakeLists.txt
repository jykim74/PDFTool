cmake_minimum_required(VERSION 3.16)

project(PDFTool
  VERSION 0.0.1
  DESCRIPTION "PDFTool Application"
  LANGUAGES CXX )


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt5 Qt6 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Gui)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set( OPENSSL "openssl35" )

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
)

add_executable(PDFTool
    ${PROJECT_SOURCES}
    man_applet.h man_applet.cpp
    js_pdf_api.h
    js_pdf_api.cpp
    common.h
    common.cpp
)

target_link_options( PDFTool PRIVATE -mwindows -MD )
target_link_libraries(PDFTool PRIVATE Qt${QT_VERSION_MAJOR}::Widgets
  PKILib crypto ltdl ssl ws2_32 qpdf)


if(WIN32)
    include_directories(
      ../../PKILib
      ../../lib/win64/qpdf
      "c:/msys64/mingw64/include"
    )

  if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
       target_link_directories( ${PROJECT_NAME} PRIVATE
       ../../PKILib/build/Desktop_Qt_5_15_2_MinGW_64_bit-Debug
       ../../lib/win64/debug/${OPENSSL}/lib64
       ../../lib/win64/qpdf/lib
       ../../lib/win64 )
   elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
       target_link_directories( ${PROJECT_NAME} PRIVATE
       ../../PKILib/build/Desktop_Qt_5_15_2_MinGW_64_bit-Release
       ../../lib/win64/${OPENSSL}/lib64
       ../../lib/win64/qpdf/lib
       ../../lib/win64 )
   endif()


elseif(APPLE)
    include_directories(
      ../../PKILib
      /usr/local/include
    )

    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug
        ../../lib/mac/debug/${OPENSSL}/lib
        /usr/local/lib )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Release
        ../../lib/mac/${OPENSSL}/lib
        /usr/local/lib )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Gui
        Qt${QT_VERSION_MAJOR}::Widgets
        PKILib crypto ssl qpdf
        "-framework AppKit"
        "-framework Carbon"
        "-framework Foundation"
        "-framework ApplicationServices" )
elseif(LINUX)

endif()

