/**
 * Memory Inspector CLI - Rich Graphics Implementation
 * 
 * Advanced CLI visualization with boxes, charts, and enhanced output
 */

#include "cli_graphics.h"
#include "memory_inspector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <math.h>

/* Global state */
static struct {
    bool colors_enabled;
    int terminal_width;
    int terminal_height;
} g_graphics_state = {0};

/**
 * Initialize graphics subsystem
 */
void cli_init_graphics(bool colors_enabled) {
    g_graphics_state.colors_enabled = colors_enabled && isatty(STDOUT_FILENO);
    g_graphics_state.terminal_width = cli_get_terminal_width();
    g_graphics_state.terminal_height = cli_get_terminal_height();
}

/**
 * Cleanup graphics subsystem
 */
void cli_cleanup_graphics(void) {
    if (g_graphics_state.colors_enabled) {
        printf(COLOR_RESET);
        fflush(stdout);
    }
}

/**
 * Get terminal width
 */
int cli_get_terminal_width(void) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
        return w.ws_col;
    }
    return 80; /* Default fallback */
}

/**
 * Get terminal height
 */
int cli_get_terminal_height(void) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
        return w.ws_row;
    }
    return 24; /* Default fallback */
}

/**
 * Clear screen
 */
void cli_clear_screen(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

/**
 * Move cursor to position
 */
void cli_move_cursor(int row, int col) {
    printf("\033[%d;%dH", row, col);
}

/**
 * Hide cursor
 */
void cli_hide_cursor(void) {
    printf("\033[?25l");
    fflush(stdout);
}

/**
 * Show cursor
 */
void cli_show_cursor(void) {
    printf("\033[?25h");
    fflush(stdout);
}

/**
 * Print colored text
 */
void cli_print_colored(const char *color, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_graphics_state.colors_enabled) {
        printf("%s", color);
    }
    vprintf(format, args);
    if (g_graphics_state.colors_enabled) {
        printf(COLOR_RESET);
    }
    
    va_end(args);
}

/**
 * Print centered text
 */
void cli_print_centered(const char *text, int width) {
    int text_len = strlen(text);
    int padding = (width - text_len) / 2;
    
    if (padding > 0) {
        printf("%*s", padding, "");
    }
    printf("%s", text);
    if (padding > 0) {
        printf("%*s", width - text_len - padding, "");
    }
}

/**
 * Print padded text
 */
void cli_print_padded(const char *text, int width, char pad_char) {
    int text_len = strlen(text);
    printf("%s", text);
    for (int i = text_len; i < width; i++) {
        printf("%c", pad_char);
    }
}

/**
 * Draw a simple box
 */
void cli_draw_box(int x, int y, int width, int height, const char *title) {
    // Top border
    cli_move_cursor(y, x);
    printf(BOX_TOP_LEFT);
    if (title && strlen(title) > 0) {
        int title_len = strlen(title);
        int title_padding = (width - title_len - 4) / 2;
        for (int i = 0; i < title_padding; i++) printf(BOX_HORIZONTAL);
        printf(" %s ", title);
        for (int i = 0; i < width - title_len - title_padding - 4; i++) printf(BOX_HORIZONTAL);
    } else {
        for (int i = 1; i < width - 1; i++) printf(BOX_HORIZONTAL);
    }
    printf(BOX_TOP_RIGHT);
    
    // Sides
    for (int i = 1; i < height - 1; i++) {
        cli_move_cursor(y + i, x);
        printf(BOX_VERTICAL);
        cli_move_cursor(y + i, x + width - 1);
        printf(BOX_VERTICAL);
    }
    
    // Bottom border
    cli_move_cursor(y + height - 1, x);
    printf(BOX_BOTTOM_LEFT);
    for (int i = 1; i < width - 1; i++) printf(BOX_HORIZONTAL);
    printf(BOX_BOTTOM_RIGHT);
}

/**
 * Draw a double-line box
 */
void cli_draw_double_box(int x, int y, int width, int height, const char *title) {
    // Top border
    cli_move_cursor(y, x);
    printf(DBOX_TOP_LEFT);
    if (title && strlen(title) > 0) {
        int title_len = strlen(title);
        int title_padding = (width - title_len - 4) / 2;
        for (int i = 0; i < title_padding; i++) printf(DBOX_HORIZONTAL);
        printf(" %s ", title);
        for (int i = 0; i < width - title_len - title_padding - 4; i++) printf(DBOX_HORIZONTAL);
    } else {
        for (int i = 1; i < width - 1; i++) printf(DBOX_HORIZONTAL);
    }
    printf(DBOX_TOP_RIGHT);
    
    // Sides
    for (int i = 1; i < height - 1; i++) {
        cli_move_cursor(y + i, x);
        printf(DBOX_VERTICAL);
        cli_move_cursor(y + i, x + width - 1);
        printf(DBOX_VERTICAL);
    }
    
    // Bottom border
    cli_move_cursor(y + height - 1, x);
    printf(DBOX_BOTTOM_LEFT);
    for (int i = 1; i < width - 1; i++) printf(DBOX_HORIZONTAL);
    printf(DBOX_BOTTOM_RIGHT);
}

/**
 * Draw separator line with title
 */
void cli_draw_separator(int width, const char *title) {
    if (title && strlen(title) > 0) {
        int title_len = strlen(title);
        int padding = (width - title_len - 6) / 2;
        
        cli_print_colored(FG_CYAN, "%s", BOX_T_RIGHT);
        for (int i = 0; i < padding; i++) {
            cli_print_colored(FG_CYAN, "%s", BOX_HORIZONTAL);
        }
        cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, " %s ", title);
        for (int i = 0; i < width - title_len - padding - 6; i++) {
            cli_print_colored(FG_CYAN, "%s", BOX_HORIZONTAL);
        }
        cli_print_colored(FG_CYAN, "%s", BOX_T_LEFT);
    } else {
        for (int i = 0; i < width; i++) {
            cli_print_colored(FG_CYAN, "%s", BOX_HORIZONTAL);
        }
    }
    printf("\n");
}

/**
 * Draw progress bar
 */
void cli_draw_progress_bar(const char *label, uint64_t value, uint64_t max_value, int width) {
    double percentage = max_value > 0 ? (double)value / max_value : 0.0;
    int filled = (int)(percentage * (width - 2));
    
    printf("%-20s ", label);
    cli_print_colored(FG_GRAY, "[");
    
    for (int i = 0; i < width - 2; i++) {
        if (i < filled) {
            if (percentage < 0.5) {
                cli_print_colored(FG_GREEN, PROGRESS_FULL);
            } else if (percentage < 0.8) {
                cli_print_colored(FG_YELLOW, PROGRESS_FULL);
            } else {
                cli_print_colored(FG_RED, PROGRESS_FULL);
            }
        } else {
            cli_print_colored(FG_GRAY, PROGRESS_EMPTY);
        }
    }
    
    cli_print_colored(FG_GRAY, "]");
    printf(" %5.1f%%\n", percentage * 100);
}

/**
 * Draw threat indicator
 */
void cli_draw_threat_indicator(threat_level_t level, const char *description) {
    const char *icon, *color, *level_name;
    
    switch (level) {
        case THREAT_NONE:
            icon = SYMBOL_CHECKMARK;
            color = STATUS_SAFE;
            level_name = "SAFE";
            break;
        case THREAT_LOW:
            icon = SYMBOL_INFO;
            color = STATUS_INFO;
            level_name = "LOW";
            break;
        case THREAT_MEDIUM:
            icon = SYMBOL_WARNING;
            color = STATUS_WARNING;
            level_name = "MEDIUM";
            break;
        case THREAT_HIGH:
            icon = SYMBOL_WARNING;
            color = STATUS_DANGER;
            level_name = "HIGH";
            break;
        case THREAT_CRITICAL:
            icon = SYMBOL_CROSS;
            color = STATUS_DANGER;
            level_name = "CRITICAL";
            break;
        default:
            icon = "?";
            color = STATUS_UNKNOWN;
            level_name = "UNKNOWN";
            break;
    }
    
    cli_print_colored(color, "%s %s", icon, level_name);
    if (description) {
        printf(": %s", description);
    }
    printf("\n");
}

/**
 * Print status with icon
 */
void cli_print_status(const char *icon, const char *color, const char *message) {
    cli_print_colored(color, "%s ", icon);
    printf("%s\n", message);
}

/**
 * Print banner - simple version without cursor positioning
 */
void cli_print_banner(const char *title, const char *subtitle) {
    printf("\n");
    cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "╔");
    for (int i = 0; i < 78; i++) cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "═");
    cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "╗\n");
    
    cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "║");
    cli_print_centered(title, 78);
    cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "║\n");
    
    if (subtitle) {
        cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "║");
        cli_print_centered(subtitle, 78);
        cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "║\n");
    }
    
    cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "╚");
    for (int i = 0; i < 78; i++) cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "═");
    cli_print_colored(FG_BRIGHT_CYAN COLOR_BOLD, "╝\n");
    printf("\n");
}

/**
 * Print hint message
 */
void cli_print_hint(const char *message) {
    cli_print_colored(FG_BRIGHT_BLUE, "%s Hint: ", SYMBOL_INFO);
    cli_print_colored(FG_BLUE, "%s\n", message);
}

/**
 * Print tip message
 */
void cli_print_tip(const char *message) {
    cli_print_colored(FG_BRIGHT_YELLOW, "%s Tip: ", SYMBOL_STAR);
    cli_print_colored(FG_YELLOW, "%s\n", message);
}

/**
 * Print warning box
 */
void cli_print_warning_box(const char *message) {
    printf("\n");
    cli_print_colored(BG_YELLOW FG_BLACK COLOR_BOLD, " %s WARNING ", SYMBOL_WARNING);
    printf("\n");
    cli_print_colored(FG_YELLOW, "%s\n", message);
    printf("\n");
}

/**
 * Print error box
 */
void cli_print_error_box(const char *message) {
    printf("\n");
    cli_print_colored(BG_RED FG_WHITE COLOR_BOLD, " %s ERROR ", SYMBOL_CROSS);
    printf("\n");
    cli_print_colored(FG_RED, "%s\n", message);
    printf("\n");
}

/**
 * Print success box
 */
void cli_print_success_box(const char *message) {
    printf("\n");
    cli_print_colored(BG_GREEN FG_BLACK COLOR_BOLD, " %s SUCCESS ", SYMBOL_CHECKMARK);
    printf("\n");
    cli_print_colored(FG_GREEN, "%s\n", message);
    printf("\n");
}

/**
 * Draw memory legend
 */
void cli_draw_memory_legend(void) {
    printf("\n");
    cli_print_colored(FG_BRIGHT_WHITE COLOR_BOLD, "Legend: ");
    cli_print_colored(STATUS_DANGER, "S");
    printf("=Suspicious, ");
    cli_print_colored(STATUS_WARNING, "I");
    printf("=Injected, ");
    cli_print_colored(STATUS_DANGER, "X");
    printf("=Write+Exec");
    printf("\n\n");
}

/**
 * Draw address range
 */
void cli_draw_address_range(uint64_t start, uint64_t end, const char *label) {
    cli_print_colored(FG_GRAY, "0x%016lx", start);
    cli_print_colored(FG_CYAN, " %s ", SYMBOL_ARROW_RIGHT);
    cli_print_colored(FG_GRAY, "0x%016lx", end);
    if (label) {
        cli_print_colored(FG_WHITE, " (%s)", label);
    }
}

/**
 * Draw permission flags with colors
 */
void cli_draw_permission_flags(int permissions) {
    if (permissions & MI_PERM_READ) {
        cli_print_colored(FG_GREEN, "r");
    } else {
        cli_print_colored(FG_GRAY, "-");
    }
    
    if (permissions & MI_PERM_WRITE) {
        if (permissions & MI_PERM_EXEC) {
            cli_print_colored(STATUS_DANGER, "w"); /* Dangerous RWX */
        } else {
            cli_print_colored(FG_YELLOW, "w");
        }
    } else {
        cli_print_colored(FG_GRAY, "-");
    }
    
    if (permissions & MI_PERM_EXEC) {
        if (permissions & MI_PERM_WRITE) {
            cli_print_colored(STATUS_DANGER, "x"); /* Dangerous RWX */
        } else {
            cli_print_colored(FG_BLUE, "x");
        }
    } else {
        cli_print_colored(FG_GRAY, "-");
    }
}