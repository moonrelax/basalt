find_package(GTest QUIET)
if(NOT GTest_FOUND)
    return()
endif()

add_executable(basalt_tests
    test_memory.cpp
    test_mmu.cpp
    test_cpu_basic.cpp
    test_cpu_sse.cpp
)

target_link_libraries(basalt_tests PRIVATE basalt_core GTest::gtest_main)
add_test(NAME basalt_tests COMMAND basalt_tests)
