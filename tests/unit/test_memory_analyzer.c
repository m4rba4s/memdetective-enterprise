/**
 * Memory Inspector CLI - Unit Tests for Memory Analyzer
 * 
 * Tests for memory analysis algorithms and anomaly detection
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

/* Test data */
static mi_memory_region_t create_test_region(uint64_t start, uint64_t end, 
                                           mi_permissions_t perms, mi_region_type_t type) {
    mi_memory_region_t region = {0};
    region.start_addr = start;
    region.end_addr = end;
    region.size = end - start;
    region.permissions = perms;
    region.type = type;
    return region;
}

/* Test 1: RWX region detection */
static void test_rwx_detection(void) {
    /* Normal executable region */
    mi_memory_region_t normal_exec = create_test_region(
        0x400000, 0x401000, MI_PERM_READ | MI_PERM_EXEC, MI_REGION_CODE
    );
    TEST_ASSERT(!detect_rwx_anomaly(&normal_exec), "Normal R-X region not flagged");
    
    /* Suspicious RWX region */
    mi_memory_region_t rwx_region = create_test_region(
        0x7f0000000000, 0x7f0000001000, 
        MI_PERM_READ | MI_PERM_WRITE | MI_PERM_EXEC, MI_REGION_UNKNOWN
    );
    TEST_ASSERT(detect_rwx_anomaly(&rwx_region), "RWX region correctly detected");
    
    /* Normal data region */
    mi_memory_region_t data_region = create_test_region(
        0x600000, 0x601000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_DATA
    );
    TEST_ASSERT(!detect_rwx_anomaly(&data_region), "Normal RW- region not flagged");
}

/* Test 2: Anonymous executable detection */
static void test_anonymous_executable_detection(void) {
    /* Anonymous executable region (suspicious) */
    mi_memory_region_t anon_exec = create_test_region(
        0x7f1000000000, 0x7f1000001000, MI_PERM_READ | MI_PERM_EXEC, MI_REGION_UNKNOWN
    );
    strcpy(anon_exec.path, "");  /* Anonymous */
    TEST_ASSERT(detect_anonymous_executable(&anon_exec), "Anonymous executable detected");
    
    /* Named executable region (normal) */
    mi_memory_region_t named_exec = create_test_region(
        0x400000, 0x401000, MI_PERM_READ | MI_PERM_EXEC, MI_REGION_CODE
    );
    strcpy(named_exec.path, "/usr/bin/test");
    TEST_ASSERT(!detect_anonymous_executable(&named_exec), "Named executable not flagged");
    
    /* Anonymous non-executable */
    mi_memory_region_t anon_data = create_test_region(
        0x600000, 0x601000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_DATA
    );
    strcpy(anon_data.path, "");
    TEST_ASSERT(!detect_anonymous_executable(&anon_data), "Anonymous data not flagged");
}

/* Test 3: Heap anomaly detection */
static void test_heap_anomaly_detection(void) {
    /* Normal heap region */
    mi_memory_region_t normal_heap = create_test_region(
        0x1000000, 0x1100000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_HEAP
    );
    strcpy(normal_heap.path, "[heap]");
    TEST_ASSERT(!detect_heap_anomaly(&normal_heap), "Normal heap not flagged");
    
    /* Executable heap (suspicious) */
    mi_memory_region_t exec_heap = create_test_region(
        0x1000000, 0x1100000, 
        MI_PERM_READ | MI_PERM_WRITE | MI_PERM_EXEC, MI_REGION_HEAP
    );
    strcpy(exec_heap.path, "[heap]");
    TEST_ASSERT(detect_heap_anomaly(&exec_heap), "Executable heap detected");
    
    /* Oversized heap region */
    mi_memory_region_t huge_heap = create_test_region(
        0x1000000, 0x20000000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_HEAP
    );
    strcpy(huge_heap.path, "[heap]");
    TEST_ASSERT(detect_heap_anomaly(&huge_heap), "Oversized heap detected");
}

/* Test 4: Stack anomaly detection */
static void test_stack_anomaly_detection(void) {
    /* Normal stack */
    mi_memory_region_t normal_stack = create_test_region(
        0x7fff00000000, 0x7fff00800000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_STACK
    );
    strcpy(normal_stack.path, "[stack]");
    TEST_ASSERT(!detect_stack_anomaly(&normal_stack), "Normal stack not flagged");
    
    /* Executable stack (suspicious) */
    mi_memory_region_t exec_stack = create_test_region(
        0x7fff00000000, 0x7fff00800000, 
        MI_PERM_READ | MI_PERM_WRITE | MI_PERM_EXEC, MI_REGION_STACK
    );
    strcpy(exec_stack.path, "[stack]");
    TEST_ASSERT(detect_stack_anomaly(&exec_stack), "Executable stack detected");
    
    /* Non-writable stack (suspicious) */
    mi_memory_region_t readonly_stack = create_test_region(
        0x7fff00000000, 0x7fff00800000, MI_PERM_READ, MI_REGION_STACK
    );
    strcpy(readonly_stack.path, "[stack]");
    TEST_ASSERT(detect_stack_anomaly(&readonly_stack), "Read-only stack detected");
}

/* Test 5: Code injection patterns */
static void test_code_injection_detection(void) {
    /* Simulate shellcode patterns */
    uint8_t shellcode_pattern[] = {
        0x90, 0x90, 0x90, 0x90,  /* NOP sled */
        0xEB, 0x1F,              /* JMP short */
        0x5E,                    /* POP ESI */
        0x89, 0x76, 0x08         /* MOV [ESI+8], ESI */
    };
    
    TEST_ASSERT(detect_shellcode_pattern(shellcode_pattern, sizeof(shellcode_pattern)), 
                "Shellcode pattern detected");
    
    /* Normal code pattern */
    uint8_t normal_code[] = {
        0x48, 0x89, 0xe5,        /* MOV RBP, RSP */
        0x48, 0x83, 0xec, 0x10,  /* SUB RSP, 16 */
        0xc3                     /* RET */
    };
    
    TEST_ASSERT(!detect_shellcode_pattern(normal_code, sizeof(normal_code)), 
                "Normal code not flagged as shellcode");
}

/* Test 6: Memory gap analysis */
static void test_memory_gap_analysis(void) {
    mi_memory_region_t regions[3];
    
    /* Normal contiguous regions */
    regions[0] = create_test_region(0x400000, 0x401000, MI_PERM_READ | MI_PERM_EXEC, MI_REGION_CODE);
    regions[1] = create_test_region(0x401000, 0x402000, MI_PERM_READ, MI_REGION_DATA);
    regions[2] = create_test_region(0x402000, 0x403000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_DATA);
    
    TEST_ASSERT(!detect_suspicious_gaps(regions, 3), "Contiguous regions have no gaps");
    
    /* Regions with suspicious gap */
    regions[1] = create_test_region(0x500000, 0x501000, MI_PERM_READ, MI_REGION_DATA);
    TEST_ASSERT(detect_suspicious_gaps(regions, 3), "Large gap detected");
}

/* Test 7: Statistical analysis */
static void test_statistical_analysis(void) {
    mi_memory_stats_t stats = {0};
    mi_memory_region_t regions[5];
    
    /* Create test regions */
    regions[0] = create_test_region(0x400000, 0x401000, MI_PERM_READ | MI_PERM_EXEC, MI_REGION_CODE);
    regions[1] = create_test_region(0x600000, 0x700000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_DATA);
    regions[2] = create_test_region(0x1000000, 0x1100000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_HEAP);
    regions[3] = create_test_region(0x7fff00000000, 0x7fff00800000, MI_PERM_READ | MI_PERM_WRITE, MI_REGION_STACK);
    regions[4] = create_test_region(0x7f0000000000, 0x7f0000001000, 
                                   MI_PERM_READ | MI_PERM_WRITE | MI_PERM_EXEC, MI_REGION_UNKNOWN);
    
    calculate_memory_statistics(regions, 5, &stats);
    
    TEST_ASSERT(stats.total_regions == 5, "Correct region count");
    TEST_ASSERT(stats.executable_regions == 2, "Correct executable region count");
    TEST_ASSERT(stats.rwx_regions == 1, "Correct RWX region count");
    TEST_ASSERT(stats.total_size > 0, "Total size calculated");
}

/* Test 8: Heuristic scoring */
static void test_heuristic_scoring(void) {
    mi_memory_region_t suspicious_region = create_test_region(
        0x7f0000000000, 0x7f0000001000, 
        MI_PERM_READ | MI_PERM_WRITE | MI_PERM_EXEC, MI_REGION_UNKNOWN
    );
    strcpy(suspicious_region.path, "");  /* Anonymous */
    
    int score = calculate_suspicion_score(&suspicious_region);
    TEST_ASSERT(score > 50, "Suspicious region has high score");
    
    mi_memory_region_t normal_region = create_test_region(
        0x400000, 0x401000, MI_PERM_READ | MI_PERM_EXEC, MI_REGION_CODE
    );
    strcpy(normal_region.path, "/usr/bin/test");
    
    score = calculate_suspicion_score(&normal_region);
    TEST_ASSERT(score < 20, "Normal region has low score");
}

/* Test 9: Comprehensive analysis */
static void test_comprehensive_analysis(void) {
    mi_memory_region_t regions[10];
    mi_analysis_result_t result = {0};
    
    /* Mix of normal and suspicious regions */
    regions[0] = create_test_region(0x400000, 0x401000, MI_PERM_READ | MI_PERM_EXEC, MI_REGION_CODE);
    strcpy(regions[0].path, "/usr/bin/test");
    
    regions[1] = create_test_region(0x7f0000000000, 0x7f0000001000, 
                                   MI_PERM_READ | MI_PERM_WRITE | MI_PERM_EXEC, MI_REGION_UNKNOWN);
    strcpy(regions[1].path, "");
    
    regions[2] = create_test_region(0x1000000, 0x1100000, 
                                   MI_PERM_READ | MI_PERM_WRITE | MI_PERM_EXEC, MI_REGION_HEAP);
    strcpy(regions[2].path, "[heap]");
    
    analyze_memory_regions(regions, 3, &result);
    
    TEST_ASSERT(result.total_regions == 3, "Correct analysis region count");
    TEST_ASSERT(result.suspicious_regions >= 2, "Suspicious regions detected");
    TEST_ASSERT(result.threat_level > MI_THREAT_LOW, "Elevated threat level detected");
}

/* Test 10: Edge cases and error handling */
static void test_edge_cases(void) {
    /* NULL pointer handling */
    TEST_ASSERT(!detect_rwx_anomaly(NULL), "NULL region handled in RWX detection");
    TEST_ASSERT(!detect_anonymous_executable(NULL), "NULL region handled in anon exec detection");
    
    /* Zero-sized region */
    mi_memory_region_t zero_region = create_test_region(0x400000, 0x400000, MI_PERM_READ, MI_REGION_CODE);
    TEST_ASSERT(!detect_rwx_anomaly(&zero_region), "Zero-sized region handled");
    
    /* Invalid permissions */
    mi_memory_region_t invalid_perms = create_test_region(0x400000, 0x401000, 0, MI_REGION_CODE);
    TEST_ASSERT(!detect_rwx_anomaly(&invalid_perms), "Invalid permissions handled");
    
    /* Empty statistics */
    mi_memory_stats_t empty_stats = {0};
    calculate_memory_statistics(NULL, 0, &empty_stats);
    TEST_ASSERT(empty_stats.total_regions == 0, "Empty region list handled");
}

/* Main test runner */
int main(void) {
    printf("=== Memory Analyzer Unit Tests ===\n\n");
    
    /* Initialize test environment */
    mi_config_t config = {
        .target_pid = getpid(),
        .verbose = false,
        .debug = true
    };
    
    if (mi_init(&config) != MI_SUCCESS) {
        fprintf(stderr, "Failed to initialize memory inspector for testing\n");
        return 1;
    }
    
    /* Run all tests */
    TEST_RUN(test_rwx_detection);
    TEST_RUN(test_anonymous_executable_detection);
    TEST_RUN(test_heap_anomaly_detection);
    TEST_RUN(test_stack_anomaly_detection);
    TEST_RUN(test_code_injection_detection);
    TEST_RUN(test_memory_gap_analysis);
    TEST_RUN(test_statistical_analysis);
    TEST_RUN(test_heuristic_scoring);
    TEST_RUN(test_comprehensive_analysis);
    TEST_RUN(test_edge_cases);
    
    /* Cleanup */
    mi_cleanup();
    
    printf("🎉 All memory analyzer tests passed!\n");
    return 0;
}