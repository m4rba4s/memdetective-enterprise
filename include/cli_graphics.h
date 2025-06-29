/**
 * Memory Inspector CLI - Rich Graphics Interface
 * 
 * Advanced CLI visualization with boxes, charts, and enhanced output
 */

#ifndef CLI_GRAPHICS_H
#define CLI_GRAPHICS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Extended ANSI color codes */
#define COLOR_RESET     "\033[0m"
#define COLOR_BOLD      "\033[1m"
#define COLOR_DIM       "\033[2m"
#define COLOR_ITALIC    "\033[3m"
#define COLOR_UNDERLINE "\033[4m"
#define COLOR_BLINK     "\033[5m"
#define COLOR_REVERSE   "\033[7m"
#define COLOR_STRIKETHROUGH "\033[9m"

/* Foreground colors */
#define FG_BLACK    "\033[30m"
#define FG_RED      "\033[31m"
#define FG_GREEN    "\033[32m"
#define FG_YELLOW   "\033[33m"
#define FG_BLUE     "\033[34m"
#define FG_MAGENTA  "\033[35m"
#define FG_CYAN     "\033[36m"
#define FG_WHITE    "\033[37m"
#define FG_GRAY     "\033[90m"
#define FG_BRIGHT_RED    "\033[91m"
#define FG_BRIGHT_GREEN  "\033[92m"
#define FG_BRIGHT_YELLOW "\033[93m"
#define FG_BRIGHT_BLUE   "\033[94m"
#define FG_BRIGHT_MAGENTA "\033[95m"
#define FG_BRIGHT_CYAN   "\033[96m"
#define FG_BRIGHT_WHITE  "\033[97m"

/* Background colors */
#define BG_BLACK    "\033[40m"
#define BG_RED      "\033[41m"
#define BG_GREEN    "\033[42m"
#define BG_YELLOW   "\033[43m"
#define BG_BLUE     "\033[44m"
#define BG_MAGENTA  "\033[45m"
#define BG_CYAN     "\033[46m"
#define BG_WHITE    "\033[47m"

/* Unicode box drawing characters */
#define BOX_HORIZONTAL      "─"
#define BOX_VERTICAL        "│"
#define BOX_TOP_LEFT        "┌"
#define BOX_TOP_RIGHT       "┐"
#define BOX_BOTTOM_LEFT     "└"
#define BOX_BOTTOM_RIGHT    "┘"
#define BOX_CROSS           "┼"
#define BOX_T_DOWN          "┬"
#define BOX_T_UP            "┴"
#define BOX_T_RIGHT         "├"
#define BOX_T_LEFT          "┤"

/* Double line box characters */
#define DBOX_HORIZONTAL     "═"
#define DBOX_VERTICAL       "║"
#define DBOX_TOP_LEFT       "╔"
#define DBOX_TOP_RIGHT      "╗"
#define DBOX_BOTTOM_LEFT    "╚"
#define DBOX_BOTTOM_RIGHT   "╝"

/* Special symbols */
#define SYMBOL_ARROW_RIGHT  "→"
#define SYMBOL_ARROW_LEFT   "←"
#define SYMBOL_ARROW_UP     "↑"
#define SYMBOL_ARROW_DOWN   "↓"
#define SYMBOL_CHECKMARK    "✓"
#define SYMBOL_CROSS        "✗"
#define SYMBOL_WARNING      "⚠"
#define SYMBOL_INFO         "ℹ"
#define SYMBOL_STAR         "★"
#define SYMBOL_BULLET       "•"
#define SYMBOL_DIAMOND      "◆"
#define SYMBOL_CIRCLE       "●"
#define SYMBOL_SQUARE       "■"
#define SYMBOL_TRIANGLE     "▲"

/* Progress bar elements */
#define PROGRESS_FULL       "█"
#define PROGRESS_PARTIAL    "▓"
#define PROGRESS_EMPTY      "░"

/* Security status colors */
#define STATUS_SAFE     FG_BRIGHT_GREEN COLOR_BOLD
#define STATUS_WARNING  FG_BRIGHT_YELLOW COLOR_BOLD
#define STATUS_DANGER   FG_BRIGHT_RED COLOR_BOLD
#define STATUS_INFO     FG_BRIGHT_CYAN COLOR_BOLD
#define STATUS_UNKNOWN  FG_GRAY

/* Data structures */
typedef enum {
    THREAT_NONE = 0,
    THREAT_LOW,
    THREAT_MEDIUM,
    THREAT_HIGH,
    THREAT_CRITICAL
} threat_level_t;

typedef struct {
    const char *title;
    const char *content;
    const char *color;
    bool border;
} info_box_t;

typedef struct {
    const char *label;
    uint64_t value;
    uint64_t max_value;
    const char *color;
} progress_item_t;

typedef struct {
    const char *category;
    const char *value;
    const char *description;
    const char *color;
} stat_item_t;

/* Function declarations */
void cli_init_graphics(bool colors_enabled);
void cli_cleanup_graphics(void);

/* Terminal utilities */
int cli_get_terminal_width(void);
int cli_get_terminal_height(void);
void cli_clear_screen(void);
void cli_move_cursor(int row, int col);
void cli_hide_cursor(void);
void cli_show_cursor(void);

/* Text formatting */
void cli_print_colored(const char *color, const char *format, ...);
void cli_print_centered(const char *text, int width);
void cli_print_padded(const char *text, int width, char pad_char);

/* Box drawing */
void cli_draw_box(int x, int y, int width, int height, const char *title);
void cli_draw_double_box(int x, int y, int width, int height, const char *title);
void cli_draw_info_box(const info_box_t *box, int x, int y, int width);
void cli_draw_separator(int width, const char *title);

/* Progress visualization */
void cli_draw_progress_bar(const char *label, uint64_t value, uint64_t max_value, int width);
void cli_draw_multi_progress(const progress_item_t *items, size_t count, int width);

/* Memory visualization */
void cli_draw_memory_map(const void *memory_regions, size_t count, int width);
void cli_draw_memory_usage_chart(uint64_t total, uint64_t used, uint64_t executable, int width);
void cli_draw_threat_indicator(threat_level_t level, const char *description);

/* Statistics tables */
void cli_draw_stats_table(const stat_item_t *stats, size_t count, const char *title);
void cli_draw_two_column_table(const char **left_items, const char **right_items, 
                              size_t count, const char *title);

/* Status indicators */
void cli_print_status(const char *icon, const char *color, const char *message);
void cli_print_security_status(threat_level_t level, const char *message);
void cli_print_banner(const char *title, const char *subtitle);

/* Interactive elements */
void cli_print_hint(const char *message);
void cli_print_tip(const char *message);
void cli_print_warning_box(const char *message);
void cli_print_error_box(const char *message);
void cli_print_success_box(const char *message);

/* Animation support */
void cli_print_spinner(int step);
void cli_print_loading_dots(int count);

/* Memory analysis specific */
void cli_draw_memory_legend(void);
void cli_draw_address_range(uint64_t start, uint64_t end, const char *label);
void cli_draw_permission_flags(int permissions);

#endif /* CLI_GRAPHICS_H */