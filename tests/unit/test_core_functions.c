/**
 * Memory Inspector CLI - Unit Tests for Core Functions
 * 
 * Tests for core engine functionality and configuration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "memory_inspector.h"

/* Test framework macros */
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "TEST FAILED: %s at %s:%d\n", message, __FILE__, __LINE__); \
            exit(1); \
        } \
        printf("✓ %s\n", message); \
    } while(0)

#define TEST_RUN(test_func) \
    do { \
        printf("Running %s...\n", #test_func); \
        test_func(); \
        printf("✓ %s passed\n\n", #test_func); \
    } while(0)

/* Test 1: Configuration validation */
static void test_config_validation(void) {
    mi_config_t config = {0};
    
    /* Valid configuration */
    config.target_pid = getpid();
    config.verbose = false;
    config.debug = false;
    TEST_ASSERT(mi_validate_config(&config) == MI_SUCCESS, "Valid config accepted");
    
    /* Invalid PID */
    config.target_pid = -1;
    TEST_ASSERT(mi_validate_config(&config) != MI_SUCCESS, "Invalid PID rejected");
    
    /* Non-existent PID */
    config.target_pid = 999999;
    TEST_ASSERT(mi_validate_config(&config) != MI_SUCCESS, "Non-existent PID rejected");
    
    /* Reset to valid */
    config.target_pid = getpid();
    TEST_ASSERT(mi_validate_config(&config) == MI_SUCCESS, "Reset to valid config works");
}

/* Test 2: Initialization and cleanup */
static void test_init_cleanup(void) {
    mi_config_t config = {
        .target_pid = getpid(),
        .verbose = false,
        .debug = false
    };
    
    /* Test initialization */
    TEST_ASSERT(mi_init(&config) == MI_SUCCESS, "Initialization succeeds");
    
    /* Test double initialization */
    TEST_ASSERT(mi_init(&config) == MI_SUCCESS, "Double initialization handled");
    
    /* Test cleanup */
    mi_cleanup();
    
    /* Test double cleanup */
    mi_cleanup();  /* Should not crash */
    
    /* Test reinitialization after cleanup */
    TEST_ASSERT(mi_init(&config) == MI_SUCCESS, "Reinitialization after cleanup works");
    mi_cleanup();
}

/* Test 3: Process information retrieval */
static void test_process_info_retrieval(void) {
    mi_config_t config = {
        .target_pid = getpid(),
        .verbose = false,
        .debug = false
    };
    
    mi_init(&config);
    
    mi_process_info_t proc_info = {0};
    mi_result_t result = mi_get_process_info(getpid(), &proc_info);
    
    TEST_ASSERT(result == MI_SUCCESS, "Process info retrieval succeeds");
    TEST_ASSERT(proc_info.pid == getpid(), "Correct PID retrieved");
    TEST_ASSERT(strlen(proc_info.name) > 0, "Process name retrieved");
    TEST_ASSERT(strlen(proc_info.exe_path) > 0, "Executable path retrieved");
    TEST_ASSERT(proc_info.region_count > 0, "Memory regions found");
    
    /* Test with invalid PID */
    result = mi_get_process_info(999999, &proc_info);
    TEST_ASSERT(result != MI_SUCCESS, "Invalid PID handled correctly");
    
    mi_cleanup();
}

/* Test 4: Memory region enumeration */
static void test_memory_region_enumeration(void) {
    mi_config_t config = {
        .target_pid = getpid(),
        .verbose = false,
        .debug = false
    };
    
    mi_init(&config);
    
    mi_memory_region_t regions[MAX_MEMORY_REGIONS];
    size_t region_count = 0;
    
    mi_result_t result = mi_enumerate_memory_regions(getpid(), regions, &region_count);
    
    TEST_ASSERT(result == MI_SUCCESS, "Memory region enumeration succeeds");
    TEST_ASSERT(region_count > 0, "At least one region found");
    TEST_ASSERT(region_count <= MAX_MEMORY_REGIONS, "Region count within limits");
    
    /* Validate region data */
    for (size_t i = 0; i < region_count; i++) {
        TEST_ASSERT(regions[i].start_addr < regions[i].end_addr, "Valid region addresses");
        TEST_ASSERT(regions[i].size == (regions[i].end_addr - regions[i].start_addr), "Correct region size");
        TEST_ASSERT(regions[i].permissions != 0, "Region has permissions");
    }
    
    mi_cleanup();
}

/* Test 5: Platform compatibility checks */
static void test_platform_compatibility(void) {
    /* Test platform detection */
    mi_platform_t platform = mi_get_platform();
    TEST_ASSERT(platform == MI_PLATFORM_LINUX, "Correct platform detected");
    
    /* Test platform capabilities */
    bool has_proc_maps = mi_platform_supports_proc_maps();
    TEST_ASSERT(has_proc_maps == true, "Platform supports /proc/maps");
    
    bool has_mem_access = mi_platform_supports_mem_access();
    TEST_ASSERT(has_mem_access == true, "Platform supports memory access");
}

/* Test 6: Error handling and edge cases */
static void test_error_handling(void) {
    /* Test with NULL pointers */
    TEST_ASSERT(mi_init(NULL) != MI_SUCCESS, "NULL config handled");
    TEST_ASSERT(mi_validate_config(NULL) != MI_SUCCESS, "NULL config validation handled");
    TEST_ASSERT(mi_get_process_info(getpid(), NULL) != MI_SUCCESS, "NULL process info handled");
    
    /* Test with invalid parameters */
    mi_config_t config = {0};
    TEST_ASSERT(mi_init(&config) != MI_SUCCESS, "Invalid config rejected");
    
    mi_memory_region_t regions[1];
    size_t region_count = 0;
    TEST_ASSERT(mi_enumerate_memory_regions(-1, regions, &region_count) != MI_SUCCESS, 
                "Invalid PID in enumeration handled");
}

/* Test 7: Thread safety */
static void test_thread_safety(void) {
    /* This is a basic test - full thread safety would require pthread testing */
    mi_config_t config = {
        .target_pid = getpid(),
        .verbose = false,
        .debug = false
    };
    
    /* Multiple init/cleanup cycles */
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(mi_init(&config) == MI_SUCCESS, "Multiple init cycles work");
        mi_cleanup();
    }
}

/* Test 8: Configuration file parsing */
static void test_config_file_parsing(void) {
    /* Create a temporary config file */
    const char *temp_config = "/tmp/test_memory_inspector.conf";
    FILE *f = fopen(temp_config, "w");
    if (f) {
        fprintf(f, "# Test configuration\n");
        fprintf(f, "verbose = true\n");
        fprintf(f, "debug = false\n");
        fprintf(f, "auto_dump = true\n");
        fprintf(f, "output_dir = /tmp/dumps\n");
        fclose(f);
        
        mi_config_t config = {0};
        config.target_pid = getpid();
        
        mi_result_t result = mi_load_config_file(temp_config, &config);
        TEST_ASSERT(result == MI_SUCCESS, "Config file parsing succeeds");
        TEST_ASSERT(config.verbose == true, "Verbose setting parsed correctly");
        TEST_ASSERT(config.debug == false, "Debug setting parsed correctly");
        
        /* Clean up */
        unlink(temp_config);
    }
}

/* Test 9: Resource management and limits */
static void test_resource_management(void) {
    mi_config_t config = {
        .target_pid = getpid(),
        .verbose = false,
        .debug = false
    };
    
    mi_init(&config);
    
    /* Test memory usage limits */
    size_t memory_usage = mi_get_memory_usage();
    TEST_ASSERT(memory_usage > 0, "Memory usage tracking works");
    TEST_ASSERT(memory_usage < MAX_MEMORY_USAGE, "Memory usage within limits");
    
    /* Test resource cleanup */
    mi_cleanup();
    
    /* After cleanup, memory usage should be minimal */
    memory_usage = mi_get_memory_usage();
    TEST_ASSERT(memory_usage < 1024, "Memory cleaned up after shutdown");
}

/* Test 10: Performance and benchmarking */
static void test_performance_benchmarks(void) {
    mi_config_t config = {
        .target_pid = getpid(),
        .verbose = false,
        .debug = false
    };
    
    mi_init(&config);
    
    /* Benchmark process info retrieval */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    mi_process_info_t proc_info = {0};
    for (int i = 0; i < 100; i++) {
        mi_get_process_info(getpid(), &proc_info);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    TEST_ASSERT(elapsed < 1.0, "Process info retrieval is fast (< 1s for 100 calls)");
    
    /* Benchmark memory region enumeration */
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    mi_memory_region_t regions[MAX_MEMORY_REGIONS];
    size_t region_count = 0;
    for (int i = 0; i < 10; i++) {
        mi_enumerate_memory_regions(getpid(), regions, &region_count);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    TEST_ASSERT(elapsed < 1.0, "Memory enumeration is fast (< 1s for 10 calls)");
    
    mi_cleanup();
}

/* Main test runner */
int main(void) {
    printf("=== Core Functions Unit Tests ===\n\n");
    
    /* Run all tests */
    TEST_RUN(test_config_validation);
    TEST_RUN(test_init_cleanup);
    TEST_RUN(test_process_info_retrieval);
    TEST_RUN(test_memory_region_enumeration);
    TEST_RUN(test_platform_compatibility);
    TEST_RUN(test_error_handling);
    TEST_RUN(test_thread_safety);
    TEST_RUN(test_config_file_parsing);
    TEST_RUN(test_resource_management);
    TEST_RUN(test_performance_benchmarks);
    
    printf("🎉 All core function tests passed!\n");
    return 0;
}