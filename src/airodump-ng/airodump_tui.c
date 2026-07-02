#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_NCURSES
#include <ncurses.h>
#endif

#include "airodump_tui.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/compat.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/utf8/verifyssid.h"

extern int is_filtered_essid(const uint8_t * essid);

#ifdef HAVE_NCURSES
static int ap_visible(const struct AP_info * ap, const struct airodump_tui_view * view)
{
	REQUIRE(ap != NULL);
	REQUIRE(view != NULL);

	if (ap->nb_pkt < view->min_pkts || time(NULL) - ap->tlast > view->berlin
		|| memcmp(ap->bssid, BROADCAST, 6) == 0)
	{
		return (0);
	}

	if (ap->security != 0 && view->f_encrypt != 0
		&& ((ap->security & view->f_encrypt) == 0))
	{
		return (0);
	}

	if (is_filtered_essid(ap->essid))
	{
		return (0);
	}

	return (1);
}

static size_t collect_visible_aps(struct AP_info * ap_end,
								  const struct airodump_tui_view * view,
								  struct AP_info *** out_rows)
{
	size_t count = 0;
	size_t cap = 16;
	struct AP_info ** rows = NULL;
	struct AP_info * ap_cur = ap_end;

	REQUIRE(view != NULL);
	REQUIRE(out_rows != NULL);

	rows = (struct AP_info **) calloc(cap, sizeof(*rows));
	ALLEGE(rows != NULL);

	while (ap_cur != NULL)
	{
		if (ap_visible(ap_cur, view))
		{
			if (count == cap)
			{
				cap *= 2;
				rows = (struct AP_info **) realloc(rows, cap * sizeof(*rows));
				ALLEGE(rows != NULL);
			}
			rows[count++] = ap_cur;
		}

		ap_cur = ap_cur->prev;
	}

	*out_rows = rows;
	return (count);
}

static size_t collect_visible_stations(struct ST_info * st_1st,
									   const struct airodump_tui_view * view,
									   struct ST_info *** out_rows)
{
	size_t count = 0;
	size_t cap = 16;
	struct ST_info ** rows = NULL;
	struct ST_info * st_cur = st_1st;

	REQUIRE(view != NULL);
	REQUIRE(out_rows != NULL);

	rows = (struct ST_info **) calloc(cap, sizeof(*rows));
	ALLEGE(rows != NULL);

	while (st_cur != NULL)
	{
		if (st_cur->base == view->selected_ap
			&& time(NULL) - st_cur->tlast <= view->berlin)
		{
			if (count == cap)
			{
				cap *= 2;
				rows = (struct ST_info **) realloc(rows, cap * sizeof(*rows));
				ALLEGE(rows != NULL);
			}
			rows[count++] = st_cur;
		}

		st_cur = st_cur->next;
	}

	*out_rows = rows;
	return (count);
}

static const char * security_std_string(unsigned int security)
{
	if (security & STD_WPA2)
	{
		if (security & AUTH_SAE) return ("WPA3");
		if (security & AUTH_OWE) return ("WPA3");
		return ("WPA2");
	}
	if (security & STD_WPA) return ("WPA");
	if (security & STD_WEP) return ("WEP");
	if (security & STD_OPN) return ("OPN");
	return ("");
}

static void security_cipher_string(char * out, size_t len, unsigned int security)
{
	if ((security & ENC_FIELD) == 0)
	{
		strlcpy(out, "", len);
		return;
	}

	if (security & ENC_CCMP)
		strlcpy(out, "CCMP", len);
	else if (security & ENC_WRAP)
		strlcpy(out, "WRAP", len);
	else if (security & ENC_TKIP)
		strlcpy(out, "TKIP", len);
	else if (security & ENC_WEP104)
		strlcpy(out, "WEP104", len);
	else if (security & ENC_WEP40)
		strlcpy(out, "WEP40", len);
	else if (security & ENC_WEP)
		strlcpy(out, "WEP", len);
	else if (security & ENC_GCMP)
		strlcpy(out, "GCMP", len);
	else if (security & ENC_GMAC)
		strlcpy(out, "GMAC", len);
	else
		strlcpy(out, "", len);
}

static void security_auth_string(char * out, size_t len, unsigned int security)
{
	if ((security & AUTH_FIELD) == 0)
	{
		strlcpy(out, "", len);
		return;
	}

	if (security & AUTH_SAE)
		strlcpy(out, "SAE", len);
	else if (security & AUTH_MGT)
		strlcpy(out, "MGT", len);
	else if (security & AUTH_CMAC)
		strlcpy(out, "CMAC", len);
	else if (security & AUTH_PSK)
		strlcpy(out, "PSK", len);
	else if (security & AUTH_OWE)
		strlcpy(out, "OWE", len);
	else if (security & AUTH_OPN)
		strlcpy(out, "OPN", len);
	else
		strlcpy(out, "", len);
}

static int power_pair(const struct AP_info * ap)
{
	if (ap->marked && ap->marked_color >= 1 && ap->marked_color <= 7)
		return (ap->marked_color);

	if (ap->avg_power >= -45) return (2);
	if (ap->avg_power >= -60) return (3);
	if (ap->avg_power >= -75) return (4);
	return (5);
}

static void draw_padded_line(int y, int x, const char * fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	mvaddnstr(y, x, buf, COLS - x - 1);
	clrtoeol();
}

static void render_ap_row(int y,
						  int cols,
						  const struct AP_info * ap,
						  int selected,
						  const struct airodump_tui_state * state,
						  const struct airodump_tui_view * view)
{
	char line[1024];
	char cipher[32];
	char auth[32];
	const char * std;
	int pair = 0;

	security_cipher_string(cipher, sizeof(cipher), ap->security);
	security_auth_string(auth, sizeof(auth), ap->security);
	std = security_std_string(ap->security);
	pair = power_pair(ap);
	if (cols < 1) cols = 1;
	if (cols > (int) sizeof(line)) cols = (int) sizeof(line);

	snprintf(line,
			 sizeof(line),
			 " %02X:%02X:%02X:%02X:%02X:%02X  %3d  %8lu  %8lu  %4d  %3d  %-4s %-7s %-4s ",
			 ap->bssid[0],
			 ap->bssid[1],
			 ap->bssid[2],
			 ap->bssid[3],
			 ap->bssid[4],
			 ap->bssid[5],
			 ap->avg_power,
			 ap->nb_bcn,
			 ap->nb_data,
			 ap->nb_dataps,
			 ap->channel,
			 std,
			 cipher,
			 auth);

	if (view->show_uptime && strlen(line) < sizeof(line) - 32)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " %14llu", ap->timestamp);
	}

	if (view->show_wps && strlen(line) < sizeof(line) - 32)
	{
		size_t used = strlen(line);
		if (ap->wps.state != 0xFF)
		{
			if (ap->wps.ap_setup_locked)
				snprintf(line + used, sizeof(line) - used, " Locked");
			else
				snprintf(line + used, sizeof(line) - used, " WPS %u.%u",
						 ap->wps.version >> 4,
						 ap->wps.version & 0xF);
		}
	}

	if (view->show_manufacturer && ap->manuf != NULL
		&& strlen(line) < sizeof(line) - 32)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " %s", ap->manuf);
	}

	if (ap->essid[0] != 0x00 && strlen(line) < sizeof(line) - 4)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " %s", ap->essid);
	}
	else if (strlen(line) < sizeof(line) - 16)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " <length:%d>",
				 ap->ssid_length);
	}

	line[cols - 1] = '\0';

	if (selected)
		attron(A_REVERSE);

	if (state->colors_enabled)
		attron(COLOR_PAIR(pair));

	mvaddnstr(y, 0, line, cols - 1);
	clrtoeol();

	if (state->colors_enabled)
		attroff(COLOR_PAIR(pair));

	if (selected)
		attroff(A_REVERSE);
}

static void render_station_row(int y,
							   int cols,
							   const struct ST_info * st,
							   const struct airodump_tui_state * state,
							   const struct airodump_tui_view * view)
{
	char line[1024];
	char probes[256];
	int i;
	size_t used = 0;

	probes[0] = '\0';
	for (i = 0; i < NB_PRB; i++)
	{
		if (st->probes[i][0] == '\0') continue;
		if (used >= sizeof(probes) - 4) break;
		snprintf(probes + used, sizeof(probes) - used, "%s%s",
				 (used > 0) ? "," : "",
				 st->probes[i]);
		used = strlen(probes);
	}
	if (cols < 1) cols = 1;
	if (cols > (int) sizeof(line)) cols = (int) sizeof(line);

	snprintf(line,
			 sizeof(line),
			 " %02X:%02X:%02X:%02X:%02X:%02X  %02X:%02X:%02X:%02X:%02X:%02X  %3d  %2d/%-2d  %4d  %8lu  %-5s  %s",
			 st->base->bssid[0],
			 st->base->bssid[1],
			 st->base->bssid[2],
			 st->base->bssid[3],
			 st->base->bssid[4],
			 st->base->bssid[5],
			 st->stmac[0],
			 st->stmac[1],
			 st->stmac[2],
			 st->stmac[3],
			 st->stmac[4],
			 st->stmac[5],
			 st->power,
			 st->rate_to / 1000000,
			 st->rate_from / 1000000,
			 st->missed,
			 st->nb_pkt,
			 (st->wpa.pmkid[0] != 0) ? "PMKID" : (st->wpa.state == 7 ? "EAPOL" : ""),
			 probes);

	line[cols - 1] = '\0';
	if (state->colors_enabled && st->marked)
		attron(COLOR_PAIR((st->marked_color >= 1 && st->marked_color <= 7)
							  ? st->marked_color
							  : 1));
	mvaddnstr(y, 0, line, cols - 1);
	clrtoeol();
	if (state->colors_enabled && st->marked)
		attroff(COLOR_PAIR((st->marked_color >= 1 && st->marked_color <= 7)
							   ? st->marked_color
							   : 1));
}

static void render_header_line(const struct airodump_tui_view * view)
{
	char line[1024];
	int i;
	int display_cols;
	size_t used = 0;

	line[0] = '\0';

	if (view->freqoption)
	{
		used += snprintf(line + used, sizeof(line) - used, " Freq");
		for (i = 0; i < view->num_cards; i++)
		{
			used += snprintf(line + used,
							 sizeof(line) - used,
							 "%s%4d",
							 (i == 0) ? " " : ",",
							 view->frequency[i]);
		}
	}
	else
	{
		used += snprintf(line + used, sizeof(line) - used, " CH");
		for (i = 0; i < view->num_cards; i++)
		{
			used += snprintf(line + used,
							 sizeof(line) - used,
							 "%s%2d",
							 (i == 0) ? " " : ",",
							 view->channel[i]);
		}
	}

	if (view->batt != NULL) used += snprintf(line + used, sizeof(line) - used, " %s", view->batt);
	if (view->elapsed_time != NULL)
		used += snprintf(line + used,
						 sizeof(line) - used,
						 "[ Elapsed: %s ]",
						 view->elapsed_time);
	if (view->message != NULL && *view->message != '\0')
		used += snprintf(line + used, sizeof(line) - used, " %s", view->message);

	if (COLS < 1) return;
	if (COLS > (int) sizeof(line)) line[sizeof(line) - 1] = '\0';
	else line[COLS - 1] = '\0';
	display_cols = MIN(COLS - 1, (int) sizeof(line) - 1);
	attron(A_BOLD);
	mvaddnstr(0, 0, line, display_cols);
	clrtoeol();
	attroff(A_BOLD);
}

static void render_status_line(const struct airodump_tui_state * state,
							   const struct airodump_tui_view * view)
{
	char line[1024];

	snprintf(line,
			 sizeof(line),
			 "F1 help | Tab switch pane | arrows scroll | PgUp/PgDn page | Home/End jump | q quit | %s%s",
			 (state->focus == 0) ? "[AP]" : " AP",
			 (state->focus == 1) ? "[STA]" : " STA");

	if (view->do_pause)
		strlcat(line, " paused", sizeof(line));

	if (COLS < 1) return;
	mvaddnstr(LINES - 1, 0, line, MIN(COLS - 1, (int) sizeof(line) - 1));
	clrtoeol();
}

static void ensure_colors(struct airodump_tui_state * state)
{
	int i;

	if (!has_colors())
	{
		state->colors_enabled = 0;
		return;
	}

	start_color();
#ifdef NCURSES_VERSION
	(void) use_default_colors();
#endif
	for (i = 1; i <= 7; i++)
		init_pair(i, i, -1);
	state->colors_enabled = 1;
}

int airodump_tui_available(void)
{
	if (!isatty(STDOUT_FILENO) || !isatty(STDIN_FILENO)) return (0);
#ifndef HAVE_NCURSES
	return (0);
#else
	return (1);
#endif
}

int airodump_tui_start(struct airodump_tui_state * state)
{
	if (state == NULL) return (0);
	memset(state, 0, sizeof(*state));

	if (!airodump_tui_available()) return (0);

	if (initscr() == NULL) return (0);

	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	set_escdelay(25);
	curs_set(0);
	ensure_colors(state);

	getmaxyx(stdscr, state->rows, state->cols);
	state->active = 1;
	state->focus = 0;
	return (1);
}

void airodump_tui_stop(struct airodump_tui_state * state)
{
	if (state == NULL || !state->active) return;
	endwin();
	state->active = 0;
}

int airodump_tui_getch(struct airodump_tui_state * state)
{
	if (state == NULL || !state->active) return (ERR);
	return (getch());
}

void airodump_tui_render(struct airodump_tui_state * state,
						 const struct airodump_tui_view * view)
{
	struct AP_info ** ap_rows = NULL;
	struct ST_info ** st_rows = NULL;
	size_t ap_count;
	size_t st_count = 0;
	int ap_height;
	int sta_height;
	int ap_visible_rows;
	int sta_visible_rows;
	size_t ap_start;
	size_t st_start;
	size_t i;
	struct AP_info * selected_ap;

	if (state == NULL || view == NULL || !state->active) return;

	if (state->resize_pending)
	{
		endwin();
		refresh();
		clear();
		state->resize_pending = 0;
	}

	getmaxyx(stdscr, state->rows, state->cols);
	state->rows = MAX(state->rows, 3);
	state->cols = MAX(state->cols, 20);

	ap_height = (view->show_ap && view->show_sta) ? MAX(6, state->rows / 2)
												   : (view->show_ap ? state->rows - 1
																	: 1);
	if (ap_height > state->rows - 2) ap_height = state->rows - 2;
	if (ap_height < 3 && view->show_ap) ap_height = state->rows - 1;
	sta_height = state->rows - ap_height - 1;
	if (sta_height < 0) sta_height = 0;

	state->ap_visible_rows = MAX(1, ap_height - 1);
	state->sta_visible_rows = MAX(1, sta_height - 1);

	erase();
	render_header_line(view);

	ap_count = collect_visible_aps(view->ap_end, view, &ap_rows);
	if (view->show_ap && ap_count > 0)
	{
		size_t selected_index = 0;

		selected_ap = view->selected_ap;
		if (selected_ap != NULL)
		{
			for (i = 0; i < ap_count; i++)
			{
				if (ap_rows[i] == selected_ap)
				{
					selected_index = i;
					break;
				}
			}
		}

		if ((size_t) state->ap_scroll > ap_count - 1)
			state->ap_scroll = (int) (ap_count - 1);
		if (state->ap_scroll < 0) state->ap_scroll = 0;
		if (selected_ap != NULL)
		{
			if ((size_t) state->ap_scroll > selected_index)
				state->ap_scroll = (int) selected_index;
			if (selected_index >= (size_t) (state->ap_scroll + state->ap_visible_rows))
			{
				state->ap_scroll
					= (int) (selected_index - state->ap_visible_rows + 1);
			}
		}
		if (state->ap_scroll > (int) ap_count - state->ap_visible_rows)
		{
			state->ap_scroll = MAX(0, (int) ap_count - state->ap_visible_rows);
		}

		ap_start = (size_t) state->ap_scroll;
		for (i = 0; i < (size_t) state->ap_visible_rows && ap_start + i < ap_count;
			 ++i)
		{
			int selected = (ap_rows[ap_start + i] == selected_ap);
			render_ap_row((int) i + 1,
						  state->cols,
						  ap_rows[ap_start + i],
						  selected,
						  state,
						  view);
		}
	}
	else if (view->show_ap)
	{
		draw_padded_line(1, 0, " No APs match the current filters.");
	}

	if (view->show_sta && state->rows - ap_height - 1 > 0)
	{
		int y = ap_height;
		char header[512];

		if (view->selected_ap != NULL)
		{
			snprintf(header,
					 sizeof(header),
					 " Stations for %02X:%02X:%02X:%02X:%02X:%02X",
					 view->selected_ap->bssid[0],
					 view->selected_ap->bssid[1],
					 view->selected_ap->bssid[2],
					 view->selected_ap->bssid[3],
					 view->selected_ap->bssid[4],
					 view->selected_ap->bssid[5]);
		}
		else
		{
			strlcpy(header, " Stations", sizeof(header));
		}

		attron(A_BOLD);
		mvaddnstr(y, 0, header, state->cols - 1);
		clrtoeol();
		attroff(A_BOLD);

		if (view->selected_ap != NULL)
		{
			st_count = collect_visible_stations(view->st_1st, view, &st_rows);
			if (st_count == 0)
			{
				draw_padded_line(y + 1, 0, " No stations associated with the selected AP.");
			}
			else
			{
				if ((size_t) state->sta_scroll > st_count - 1)
					state->sta_scroll = (int) (st_count - 1);
				if (state->sta_scroll < 0) state->sta_scroll = 0;
				if (state->focus == 1
					&& (size_t) state->sta_scroll >= st_count)
					state->sta_scroll = 0;

				st_start = (size_t) state->sta_scroll;
				for (i = 0; i < (size_t) state->sta_visible_rows
								&& st_start + i < st_count;
					 ++i)
				{
				render_station_row(y + 1 + (int) i,
								   state->cols,
								   st_rows[st_start + i],
								   state,
								   view);
				}
			}
		}
		else
		{
			draw_padded_line(y + 1, 0, " Select an AP to view station details.");
		}
	}

	render_status_line(state, view);
	wnoutrefresh(stdscr);
	doupdate();

free(ap_rows);
free(st_rows);
}

#else
#ifndef ERR
#define ERR (-1)
#endif
int airodump_tui_available(void) { return (0); }
int airodump_tui_start(struct airodump_tui_state * state)
{
	UNUSED_PARAM(state);
	return (0);
}
void airodump_tui_stop(struct airodump_tui_state * state)
{
	UNUSED_PARAM(state);
}
int airodump_tui_getch(struct airodump_tui_state * state)
{
	UNUSED_PARAM(state);
	return (ERR);
}
void airodump_tui_render(struct airodump_tui_state * state,
						 const struct airodump_tui_view * view)
{
	UNUSED_PARAM(state);
	UNUSED_PARAM(view);
}
#endif
