#ifndef AIRODUMP_NG_TUI_H
#define AIRODUMP_NG_TUI_H

#include "airodump-ng.h"

#ifdef HAVE_NCURSES
#include <ncurses.h>
#endif

struct airodump_tui_state
{
	int active;
	int rows;
	int cols;
	int ap_scroll;
	int sta_scroll;
	int focus; /* 0 = AP pane, 1 = station pane */
	int resize_pending;
	int colors_enabled;
	int ap_visible_rows;
	int sta_visible_rows;
};

struct airodump_tui_view
{
	struct AP_info * ap_1st;
	struct AP_info * ap_end;
	struct ST_info * st_1st;
	struct AP_info * selected_ap;
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
void airodump_tui_render(struct airodump_tui_state * state,
						 const struct airodump_tui_view * view);

#endif
