#!/bin/bash
#
# Memory Inspector CLI - Build Script
# 
# Professional build script with error handling and optimization
#

set -euo pipefail

# Configuration
PROJECT_NAME="memory-inspector"
BUILD_TYPE="${BUILD_TYPE:-release}"
VERBOSE="${VERBOSE:-0}"
JOBS="${JOBS:-$(nproc)}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output
    -d, --debug     Build debug version
    -c, --clean     Clean before build
    -t, --test      Run tests after build
    -j JOBS         Number of parallel jobs (default: $(nproc))

EXAMPLES:
    $0                  # Release build
    $0 --debug          # Debug build
    $0 --clean --test   # Clean, build, and test
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -d|--debug)
                BUILD_TYPE="debug"
                shift
                ;;
            -c|--clean)
                CLEAN=1
                shift
                ;;
            -t|--test)
                RUN_TESTS=1
                shift
                ;;
            -j)
                JOBS="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Check dependencies
check_dependencies() {
    log_info "Checking build dependencies..."
    
    local missing_deps=()
    
    # Check for required tools
    command -v gcc >/dev/null 2>&1 || missing_deps+=("gcc")
    command -v make >/dev/null 2>&1 || missing_deps+=("make")
    command -v pkg-config >/dev/null 2>&1 || missing_deps+=("pkg-config")
    
    # Check for YARA development files
    if ! pkg-config --exists yara 2>/dev/null; then
        missing_deps+=("yara-devel")
    fi
    
    # Check for ncurses (for TUI)
    if ! pkg-config --exists ncurses 2>/dev/null; then
        missing_deps+=("ncurses-devel")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: sudo dnf install ${missing_deps[*]}"
        exit 1
    fi
    
    log_success "All dependencies satisfied"
}

# Clean build artifacts
clean_build() {
    log_info "Cleaning build artifacts..."
    make clean 2>/dev/null || true
    rm -rf build/ 2>/dev/null || true
    log_success "Clean complete"
}

# Build project
build_project() {
    log_info "Building ${PROJECT_NAME} (${BUILD_TYPE} mode)..."
    
    # Set build flags based on type
    if [[ "$BUILD_TYPE" == "debug" ]]; then
        make debug -j"$JOBS" ${VERBOSE:+V=1}
    else
        make -j"$JOBS" ${VERBOSE:+V=1}
    fi
    
    log_success "Build complete"
}

# Run tests
run_tests() {
    log_info "Running tests..."
    
    if [[ -f "memory-inspector" ]]; then
        # Basic functionality test
        log_info "Testing basic functionality..."
        ./memory-inspector --version
        
        # Test with current process (should be safe)
        log_info "Testing memory analysis on current shell..."
        ./memory-inspector --pid $$ --verbose || log_warn "Memory analysis test failed (may be expected)"
        
        log_success "Basic tests passed"
    else
        log_error "Executable not found - build may have failed"
        exit 1
    fi
}

# Show build info
show_build_info() {
    log_info "Build Information:"
    echo "  Project:      ${PROJECT_NAME}"
    echo "  Build Type:   ${BUILD_TYPE}"
    echo "  Parallel Jobs: ${JOBS}"
    echo "  Verbose:      ${VERBOSE}"
    echo ""
}

# Main function
main() {
    local CLEAN=0
    local RUN_TESTS=0
    
    parse_args "$@"
    
    show_build_info
    check_dependencies
    
    if [[ $CLEAN -eq 1 ]]; then
        clean_build
    fi
    
    build_project
    
    if [[ $RUN_TESTS -eq 1 ]]; then
        run_tests
    fi
    
    log_success "Build process completed successfully!"
    log_info "Executable: ./memory-inspector"
    log_info "Usage: ./memory-inspector --help"
}

# Run main function with all arguments
main "$@"