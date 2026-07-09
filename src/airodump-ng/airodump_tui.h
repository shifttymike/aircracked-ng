#ifndef AIRODUMP_NG_TUI_H
#define AIRODUMP_NG_TUI_H

#include "airodump-ng.h"
#include <stddef.h>
#include <time.h>

#include <ncurses.h>

#define STA_SORT_BY_NOTHING 0
#define STA_SORT_BY_BSSID 1
#define STA_SORT_BY_STATION 2
#define STA_SORT_BY_BAND 3
#define STA_SORT_BY_LA 4
#define STA_SORT_BY_POWER 5
#define STA_SORT_BY_RATE 6
#define STA_SORT_BY_LOST 7
#define STA_SORT_BY_FRAMES 8
#define STA_SORT_BY_NOTES 9
#define STA_SORT_BY_PROBES 10
#define STA_SORT_BY_LAST_SEEN 11
#define STA_SORT_MAX 11
#define AIRODUMP_TUI_MAX_CHANNEL_STATUS 128

enum airodump_tui_channel_status
{
	AIRODUMP_TUI_CHANNEL_STATUS_OK = 0,
	AIRODUMP_TUI_CHANNEL_STATUS_UNAVAILABLE = 1,
	AIRODUMP_TUI_CHANNEL_STATUS_REFUSED = 2
};

enum airodump_tui_message_style
{
	AIRODUMP_TUI_MESSAGE_STYLE_DEFAULT = 0,
	AIRODUMP_TUI_MESSAGE_STYLE_WARNING = 1,
	AIRODUMP_TUI_MESSAGE_STYLE_SUCCESS = 2
};

struct airodump_tui_state
{
	int active;
	int rows;
	int cols;
	int ap_scroll;
	int sta_scroll;
	int msg_scroll;
	int msg_follow_latest;
	int focus; /* 0 = AP pane, 1 = station pane, 2 = message pane */
	int resize_pending;
	int colors_enabled;
	int mouse_enabled;
	int help_visible;
	int channel_overlay_visible;
	int sta_sort_by;
	int sta_sort_inv;
	int ap_visible_rows;
	int sta_visible_rows;
	int msg_visible_rows;
	int ap_box_top;
	int ap_box_left;
	int ap_box_width;
	int ap_box_height;
	int sta_box_top;
	int sta_box_left;
	int sta_box_width;
	int sta_box_height;
	int msg_box_top;
	int msg_box_left;
	int msg_box_width;
	int msg_box_height;
};

struct airodump_tui_channel_entry
{
	int channel;
	int frequency;
	enum airodump_tui_channel_status status;
	int validated;
};

struct airodump_tui_message_entry
{
	time_t timestamp;
	enum airodump_tui_message_style style;
	char text[512];
};

struct airodump_tui_view
{
	struct AP_info * ap_1st;
	struct AP_info * ap_end;
	struct ST_info * st_1st;
	struct AP_info * selected_ap;
	const struct airodump_tui_message_entry * messages;
	size_t message_count;
	unsigned int f_encrypt;
	unsigned long min_pkts;
	int berlin;
	int asso_client;
	int show_ap;
	int show_sta;
	int show_ack;
	int singlechan;
	int show_uptime;
	int show_manufacturer;
	int show_wps;
	int freqoption;
	int show_ax_channels;
	const char * band_label;
	const char * regdom_label;
	int regdom_self_managed;
	const struct airodump_tui_channel_entry * channel_status;
	size_t channel_status_count;
	int num_cards;
	int channel[MAX_CARDS];
	int frequency[MAX_CARDS];
	char * message;
	char * batt;
	char * elapsed_time;
	int do_pause;
	int background_mode;
	int sort_by;
	int sort_inv;
};

int airodump_tui_available(void);
int airodump_tui_start(struct airodump_tui_state * state);
void airodump_tui_stop(struct airodump_tui_state * state);
int airodump_tui_getch(struct airodump_tui_state * state);
void airodump_tui_set_mouse_enabled(struct airodump_tui_state * state, int enabled);
void airodump_tui_render(struct airodump_tui_state * state,
						 const struct airodump_tui_view * view);
int airodump_tui_ap_sort_field_from_mouse(const struct airodump_tui_state * state,
										  int x,
										  int y);
int airodump_tui_station_sort_field_from_mouse(const struct airodump_tui_state * state,
											   int x,
											   int y);
int airodump_tui_cycle_ap_sort_field(int sort_by, int direction);
int airodump_tui_cycle_station_sort_field(int sort_by, int direction);

#endif
