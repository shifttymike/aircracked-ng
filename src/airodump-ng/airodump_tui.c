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

static int visible_unassociated_station_count(const struct airodump_tui_view * view)
{
	struct ST_info * st_cur;
	int count = 0;

	REQUIRE(view != NULL);

	st_cur = view->st_1st;
	while (st_cur != NULL)
	{
		if (time(NULL) - st_cur->tlast <= view->berlin
			&& st_cur->base != NULL
			&& memcmp(st_cur->base->bssid, BROADCAST, 6) == 0)
		{
			count++;
		}
		st_cur = st_cur->next;
	}

	return (count);
}

static struct AP_info * find_unassociated_ap(struct AP_info * ap_end)
{
	struct AP_info * ap_cur = ap_end;

	while (ap_cur != NULL)
	{
		if (memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
			return (ap_cur);
		ap_cur = ap_cur->prev;
	}

	return (NULL);
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

	if (visible_unassociated_station_count(view) > 0)
	{
		struct AP_info * unassoc_ap = find_unassociated_ap(ap_end);

		if (unassoc_ap != NULL)
		{
			if (count == cap)
			{
				cap *= 2;
				rows = (struct AP_info **) realloc(rows, cap * sizeof(*rows));
				ALLEGE(rows != NULL);
			}
			rows[count++] = unassoc_ap;
		}
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
		if (time(NULL) - st_cur->tlast <= view->berlin
			&& (view->selected_ap == NULL || st_cur->base == view->selected_ap))
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

static void fill_inner_width(int y, int x, int width)
{
	if (width > 0)
		mvhline(y, x, ' ', width);
}

static void render_ap_header_row(int y,
								 int x,
								 int width,
								 const struct airodump_tui_view * view)
{
	char line[1024];
	size_t used = 0;

	line[0] = ' ';
	used = snprintf(line + 1,
					sizeof(line) - 1,
					" %-17s  %3s  %8s  %8s  %4s  %3s  %4s  %-4s %-7s %-4s",
					"BSSID",
					"PWR",
					"Beacons",
					"#Data",
					"#/s",
					"CH",
					"MB",
					"ENC",
					"CIPHER",
					"AUTH");
	if (view->show_uptime && used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, " %14s", "UPTIME");
	if (view->show_wps && used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, "  %-4s", "WPS");
	if (view->show_manufacturer && used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, "  %-12s", "MANUFACTURER");
	if (used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, "  %s", "ESSID");

	if (width < 1) width = 1;
	if (width > (int) sizeof(line) - 1) width = (int) sizeof(line) - 1;
	line[width] = '\0';
	attron(A_BOLD);
	mvaddnstr(y, x, line, width);
	fill_inner_width(y, x + (int) strlen(line), width - (int) strlen(line));
	attroff(A_BOLD);
}

static void render_station_header_row(int y, int x, int width)
{
	static const char * header =
		" BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes";
	int used;

	if (width < 1) width = 1;
	used = (int) strlen(header);
	if (used > width) used = width;
	attron(A_BOLD);
	mvaddnstr(y, x, header, used);
	fill_inner_width(y, x + used, width - used);
	attroff(A_BOLD);
}

static int render_message_row(int y,
							  int x,
							  int width,
							  int max_rows,
							  const struct airodump_tui_message_entry * entry)
{
	char ts[32];
	struct tm * lt;
	int prefix_len;
	int rows_used = 0;
	const char * cursor;

	if (width < 1) width = 1;
	if (max_rows < 1) return (0);

	lt = localtime(&(entry->timestamp));
	if (lt != NULL)
	{
		if (strftime(ts, sizeof(ts), "%H:%M:%S", lt) == 0)
			strlcpy(ts, "--:--:--", sizeof(ts));
	}
	else
	{
		strlcpy(ts, "--:--:--", sizeof(ts));
	}

	prefix_len = (int) strlen(ts) + 1;
	if (width <= prefix_len)
	{
		mvaddnstr(y, x, ts, width);
		fill_inner_width(y, x + width, 0);
		return (1);
	}

	cursor = entry->text;
	while (*cursor != '\0' && rows_used < max_rows)
	{
		int available = width - prefix_len;
		int segment_len = 0;
		int last_space = -1;
		const char * segment = cursor;

		while (*segment == ' ')
			segment++;
		if (*segment == '\0')
			break;

		if (rows_used == 0)
			mvaddnstr(y + rows_used, x, ts, (int) strlen(ts));
		else
			fill_inner_width(y + rows_used, x, prefix_len - 1);
		mvaddch(y + rows_used, x + prefix_len - 1, ' ');

		if (available < 1)
			available = 1;

		while (segment[segment_len] != '\0' && segment_len < available)
		{
			if (segment[segment_len] == ' ')
				last_space = segment_len;
			segment_len++;
		}

		if (segment[segment_len] != '\0' && last_space > 0 && last_space < segment_len)
			segment_len = last_space;
		if (segment_len < 1)
			segment_len = 1;

		mvaddnstr(y + rows_used, x + prefix_len, segment, segment_len);
		fill_inner_width(y + rows_used, x + prefix_len + segment_len, width - prefix_len - segment_len);

		cursor = segment + segment_len;
		while (*cursor == ' ')
			cursor++;
		rows_used++;
	}

	if (rows_used == 0)
	{
		mvaddnstr(y, x, ts, (int) strlen(ts));
		fill_inner_width(y, x + (int) strlen(ts), width - (int) strlen(ts));
		rows_used = 1;
	}

	return (rows_used);
}

static void draw_padded_line(int y, int x, int width, const char * fmt, ...)
{
	char buf[1024];
	va_list ap;
	int max_width;
	int used;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	max_width = width;
	if (max_width < 1) max_width = 1;
	used = (int) strlen(buf);
	if (used > max_width) used = max_width;
	mvaddnstr(y, x, buf, used);
	fill_inner_width(y, x + used, max_width - used);
}

static void render_ap_row(int y,
						  int x,
						  int width,
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
	if (width < 2) width = 2;
	if (width > (int) sizeof(line) - 1) width = (int) sizeof(line) - 1;

	line[0] = selected ? '>' : ' ';
	snprintf(line + 1,
			 sizeof(line) - 1,
			 " %02X:%02X:%02X:%02X:%02X:%02X  %3d  %8lu  %8lu  %4d  %3d  %4d  %-4s %-7s %-4s ",
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
			 ap->max_speed,
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
	else if (memcmp(ap->bssid, BROADCAST, 6) == 0 && strlen(line) < sizeof(line) - 24)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " (unassociated clients)");
	}
	else if (strlen(line) < sizeof(line) - 16)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " <length:%d>",
				 ap->ssid_length);
	}

	line[width] = '\0';

	if (selected)
		attron(A_BOLD);

	if (state->colors_enabled)
		attron(COLOR_PAIR(pair));

	mvaddnstr(y, x, line, width);
	fill_inner_width(y, x + (int) strlen(line), width - (int) strlen(line));

	if (state->colors_enabled)
		attroff(COLOR_PAIR(pair));

	if (selected)
		attroff(A_BOLD);
}

static size_t measure_ap_row_width(const struct AP_info * ap,
								   int selected,
								   const struct airodump_tui_view * view)
{
	char line[1024];
	char cipher[32];
	char auth[32];
	const char * std;

	security_cipher_string(cipher, sizeof(cipher), ap->security);
	security_auth_string(auth, sizeof(auth), ap->security);
	std = security_std_string(ap->security);

	line[0] = selected ? '>' : ' ';
	snprintf(line + 1,
			 sizeof(line) - 1,
			 " %02X:%02X:%02X:%02X:%02X:%02X  %3d  %8lu  %8lu  %4d  %3d  %4d  %-4s %-7s %-4s ",
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
			 ap->max_speed,
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
	else if (memcmp(ap->bssid, BROADCAST, 6) == 0 && strlen(line) < sizeof(line) - 24)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " (unassociated clients)");
	}
	else if (strlen(line) < sizeof(line) - 16)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, " <length:%d>",
				 ap->ssid_length);
	}

	return (strlen(line));
}

static size_t measure_ap_header_width(const struct airodump_tui_view * view)
{
	char line[1024];
	size_t used = 0;

	line[0] = ' ';
	used = snprintf(line + 1,
					sizeof(line) - 1,
					" %-17s  %3s  %8s  %8s  %4s  %3s  %4s  %-4s %-7s %-4s",
					"BSSID",
					"PWR",
					"Beacons",
					"#Data",
					"#/s",
					"CH",
					"MB",
					"ENC",
					"CIPHER",
					"AUTH");
	if (view->show_uptime && used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, " %14s", "UPTIME");
	if (view->show_wps && used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, "  %-4s", "WPS");
	if (view->show_manufacturer && used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, "  %-12s", "MANUFACTURER");
	if (used < sizeof(line) - 1)
		used += snprintf(line + 1 + used, sizeof(line) - 1 - used, "  %s", "ESSID");

	return (strlen(line));
}

static void render_station_row(int y,
							   int x,
							   int width,
							   const struct ST_info * st,
							   const struct airodump_tui_state * state,
							   const struct airodump_tui_view * view)
{
	char line[1024];
	char probes[256];
	char bssid[32];
	const char * assoc_label = NULL;
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
	if (width < 1) width = 1;
	if (width > (int) sizeof(line) - 1) width = (int) sizeof(line) - 1;

	if (st->base != NULL && memcmp(st->base->bssid, BROADCAST, 6) != 0)
	{
		snprintf(bssid,
				 sizeof(bssid),
				 "%02X:%02X:%02X:%02X:%02X:%02X",
				 st->base->bssid[0],
				 st->base->bssid[1],
				 st->base->bssid[2],
				 st->base->bssid[3],
				 st->base->bssid[4],
				 st->base->bssid[5]);
	}
	else
	{
		strlcpy(bssid, "(not associated)", sizeof(bssid));
	}

	if (st->base != NULL && memcmp(st->base->bssid, BROADCAST, 6) == 0)
		assoc_label = "unassociated";

	snprintf(line,
			 sizeof(line),
			 " %-17s  %02X:%02X:%02X:%02X:%02X:%02X  %3d  %2d/%-2d  %4d  %8lu  %-5s  %s",
			 bssid,
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

	if (assoc_label != NULL && strlen(line) < sizeof(line) - 24)
	{
		size_t line_used = strlen(line);
		snprintf(line + line_used, sizeof(line) - line_used, " [%s]", assoc_label);
	}

	line[width] = '\0';
	if (state->colors_enabled && st->marked)
		attron(COLOR_PAIR((st->marked_color >= 1 && st->marked_color <= 7)
							  ? st->marked_color
							  : 1));
	mvaddnstr(y, x, line, width);
	fill_inner_width(y, x + (int) strlen(line), width - (int) strlen(line));
	if (state->colors_enabled && st->marked)
		attroff(COLOR_PAIR((st->marked_color >= 1 && st->marked_color <= 7)
							   ? st->marked_color
							   : 1));
}

static void draw_scrollbar(int top,
						   int height,
						   int total,
						   int scroll,
						   int visible,
						   int x,
						   int active)
{
	int track;
	int thumb;
	int thumb_top;
	int thumb_bottom;
	int i;

	if (x < 0 || height < 2 || total <= visible) return;

	track = height;
	if (track < 2) return;

	if (visible < 1) visible = 1;
	if (total < 1) total = 1;
	if (scroll < 0) scroll = 0;
	if (scroll > total - visible) scroll = MAX(0, total - visible);

	thumb = (visible * track) / total;
	if (thumb < 1) thumb = 1;
	if (thumb > track) thumb = track;

	if (total == visible)
		thumb_top = 0;
	else
		thumb_top = (scroll * (track - thumb)) / (total - visible);
	thumb_bottom = thumb_top + thumb;
	if (thumb_bottom > track) thumb_bottom = track;

	for (i = 0; i < track; i++)
	{
		int y = top + i;

		if (y < 0 || y >= LINES) continue;
		if (i >= thumb_top && i < thumb_bottom)
		{
			if (active)
				attron(A_REVERSE);
			mvaddch(y, x, ACS_CKBOARD);
			if (active)
				attroff(A_REVERSE);
		}
		else
		{
			mvaddch(y, x, ACS_VLINE);
		}
	}
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

static void render_pane_box(int top, int left, int height, int cols, const char * title, int active)
{
	char line[256];
	size_t title_len;

	if (cols < 3 || height < 2) return;
	title_len = strlen(title);
	if (title_len > sizeof(line) - 4) title_len = sizeof(line) - 4;
	snprintf(line, sizeof(line), " %.*s ", (int) title_len, title);
	attron(A_BOLD);
	if (active) attron(A_REVERSE);
	mvaddch(top, left, ACS_ULCORNER);
	mvhline(top, left + 1, ACS_HLINE, cols - 2);
	mvaddch(top, left + cols - 1, ACS_URCORNER);
	mvaddnstr(top, left + 2, line, MIN((int) strlen(line), cols - 4));
	if (height >= 3)
	{
		int y;

		for (y = top + 1; y < top + height - 1; y++)
		{
			mvaddch(y, left, ACS_VLINE);
			mvaddch(y, left + cols - 1, ACS_VLINE);
		}
		mvaddch(top + height - 1, left, ACS_LLCORNER);
		mvhline(top + height - 1, left + 1, ACS_HLINE, cols - 2);
		mvaddch(top + height - 1, left + cols - 1, ACS_LRCORNER);
	}
	else
	{
		mvaddch(top + 1, left, ACS_LLCORNER);
		mvhline(top + 1, left + 1, ACS_HLINE, cols - 2);
		mvaddch(top + 1, left + cols - 1, ACS_LRCORNER);
	}
	if (active) attroff(A_REVERSE);
	attroff(A_BOLD);
}

static void render_status_line(const struct airodump_tui_state * state,
							   const struct airodump_tui_view * view)
{
	char line[1024];

	snprintf(line,
			 sizeof(line),
			 "F1 help | Tab/Left/Right switch pane | arrows scroll | PgUp/PgDn page | Home/End jump | q quit | Focus: %s",
			 (state->focus == 1) ? "STA" : (state->focus == 2) ? "MSG" : "AP");

	if (view->selected_ap == NULL)
		strlcat(line, " stations: all", sizeof(line));
	else if (memcmp(view->selected_ap->bssid, BROADCAST, 6) == 0)
		strlcat(line, " stations: unassociated", sizeof(line));
	else
		strlcat(line, " stations: selected AP", sizeof(line));

	if (view->show_ap && view->show_sta)
	{
		strlcat(line, (state->focus == 0) ? " [AP]" : " AP", sizeof(line));
		strlcat(line, (state->focus == 1) ? " [STA]" : " STA", sizeof(line));
	}
	else if (view->show_ap)
	{
		strlcat(line, " [AP only]", sizeof(line));
	}
	else if (view->show_sta)
	{
		strlcat(line, " [STA only]", sizeof(line));
	}

	strlcat(line, "  c clear AP filter", sizeof(line));
	strlcat(line, "  d run log_sta", sizeof(line));
	strlcat(line, "  r resume hop", sizeof(line));
	strlcat(line, "  R realtime sort", sizeof(line));

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
	int stdin_tty;
	int stdout_tty;

	stdin_tty = isatty(STDIN_FILENO);
	stdout_tty = isatty(STDOUT_FILENO);
	if (!stdout_tty || !stdin_tty)
	{
		return (0);
	}
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

	if (!airodump_tui_available())
	{
		return (0);
	}

	if (initscr() == NULL)
	{
		return (0);
	}

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
	state->msg_follow_latest = 1;
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
	int sta_top;
	int content_rows;
	int top_height;
	size_t ap_start;
	size_t st_start;
	size_t i;
	struct AP_info * selected_ap;
	int ap_box_top;
	int ap_box_left;
	int ap_box_width;
	int sta_box_top;
	int sta_box_left;
	int sta_box_width;
	int msg_box_top;
	int msg_box_left;
	int msg_box_width = 0;
	int msg_enabled;

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
	content_rows = MAX(1, state->rows - 2);
	msg_enabled = (view->show_ap && state->cols >= 90);

	if (view->show_ap)
	{
		if (view->show_sta)
		{
			ap_height = MAX(4, (content_rows * 40) / 100);
			if (ap_height > content_rows - 4)
				ap_height = MAX(4, content_rows - 4);
		}
		else
		{
			ap_height = content_rows;
		}
	}
	else
	{
		ap_height = 0;
	}
	top_height = ap_height;
	ap_box_width = state->cols;

	if (view->show_sta)
	{
		sta_top = view->show_ap ? (ap_height + 1) : 1;
		if (view->show_ap)
			sta_height = MAX(4, content_rows - ap_height);
		else
			sta_height = content_rows;
	}
	else
	{
		sta_top = 0;
		sta_height = 0;
	}

	state->ap_visible_rows = MAX(1, ap_height - 3);
	state->sta_visible_rows = MAX(1, sta_height - 3);
	state->msg_visible_rows = MAX(1, top_height - 2);

	erase();
	render_header_line(view);

	ap_count = collect_visible_aps(view->ap_end, view, &ap_rows);
	if (view->show_ap && ap_count > 0)
	{
		size_t selected_index = 0;
		size_t ap_width = measure_ap_header_width(view);

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

		for (i = 0; i < ap_count; i++)
		{
			size_t row_width = measure_ap_row_width(ap_rows[i], ap_rows[i] == selected_ap, view);

			if (row_width > ap_width)
				ap_width = row_width;
		}
		if (ap_width + 2 > (size_t) state->cols)
			ap_width = (state->cols > 2) ? (size_t) state->cols - 2 : 1;
		ap_box_width = (int) ap_width + 2;
		if (msg_enabled && state->cols - ap_box_width < 24)
			ap_box_width = state->cols - 24;
		if (ap_box_width < 24)
			ap_box_width = 24;

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

		ap_box_top = 1;
		ap_box_left = 0;
		render_pane_box(ap_box_top, ap_box_left, ap_height, ap_box_width, " Access Points", state->focus == 0);
		render_ap_header_row(ap_box_top + 1, ap_box_left + 1, ap_box_width - 2, view);
		ap_start = (size_t) state->ap_scroll;
		for (i = 0; i < (size_t) state->ap_visible_rows && ap_start + i < ap_count;
			 ++i)
		{
			int selected = (ap_rows[ap_start + i] == selected_ap);
			render_ap_row((int) i + 3,
						  ap_box_left + 1,
						  ap_box_width - 2,
						  ap_rows[ap_start + i],
						  selected,
						  state,
						  view);
		}
		draw_scrollbar(ap_box_top + 2,
					   state->ap_visible_rows,
					   (int) ap_count,
					   state->ap_scroll,
					   state->ap_visible_rows,
					   ap_box_left + ap_box_width - 2,
					   state->focus == 0);
	}
	else if (view->show_ap)
	{
		size_t ap_width = measure_ap_header_width(view);

		ap_box_top = 1;
		ap_height = MAX(4, ap_height);
		ap_box_left = 0;
		if (ap_width + 2 > (size_t) state->cols)
			ap_width = (state->cols > 2) ? (size_t) state->cols - 2 : 1;
		ap_box_width = (int) ap_width + 2;
		if (msg_enabled && state->cols - ap_box_width < 24)
			ap_box_width = state->cols - 24;
		if (ap_box_width < 24)
			ap_box_width = 24;
		render_pane_box(ap_box_top, ap_box_left, ap_height, ap_box_width, " Access Points", state->focus == 0);
		render_ap_header_row(ap_box_top + 1, ap_box_left + 1, ap_box_width - 2, view);
		draw_padded_line(ap_box_top + 2, ap_box_left + 1, ap_box_width - 2, " No APs match the current filters.");
	}

	if (msg_enabled)
	{
		size_t msg_count;
		size_t msg_start;
		char title[128];

		strlcpy(title, " Messages", sizeof(title));

		msg_box_width = state->cols - ap_box_width;
		if (msg_box_width < 24)
		{
			msg_enabled = 0;
			msg_box_width = 0;
		}
		else
		{
			msg_box_top = 1;
			msg_box_left = ap_box_width;
			render_pane_box(msg_box_top, msg_box_left, top_height, msg_box_width, title, state->focus == 2);
		}

		if (msg_enabled)
		{
			msg_count = view->message_count;
			if (msg_count == 0)
			{
				draw_padded_line(msg_box_top + 1, msg_box_left + 1, msg_box_width - 2, " No messages yet.");
			}
		else
		{
			int max_scroll = 0;

			if (msg_count > (size_t) state->msg_visible_rows)
				max_scroll = MAX(0, (int) msg_count - state->msg_visible_rows);

			if (state->msg_follow_latest)
				state->msg_scroll = max_scroll;
			if ((size_t) state->msg_scroll > msg_count - 1)
				state->msg_scroll = (int) (msg_count - 1);
			if (state->msg_scroll < 0) state->msg_scroll = 0;
			if (msg_count <= (size_t) state->msg_visible_rows)
				state->msg_scroll = 0;
			else if ((size_t) state->msg_scroll > msg_count - state->msg_visible_rows)
				state->msg_scroll = max_scroll;

			msg_start = (size_t) state->msg_scroll;
			{
					int msg_y = msg_box_top + 1;
					int rows_left = state->msg_visible_rows;

					for (i = 0; msg_start + i < msg_count && rows_left > 0; ++i)
					{
						int used_rows;

						used_rows = render_message_row(msg_y,
													   msg_box_left + 1,
													   msg_box_width - 2,
													   rows_left,
													   &(view->messages[msg_start + i]));
						if (used_rows <= 0)
							break;
						msg_y += used_rows;
						rows_left -= used_rows;
					}
				}
				draw_scrollbar(msg_box_top + 1,
						   state->msg_visible_rows,
						   (int) msg_count,
						   state->msg_scroll,
						   state->msg_visible_rows,
						   msg_box_left + msg_box_width - 2,
						   state->focus == 2);
			}
		}
	}

	if (view->show_sta && state->rows - sta_top - 1 > 0)
	{
		char header[512];
		int body_top;

		if (view->selected_ap != NULL)
		{
			if (memcmp(view->selected_ap->bssid, BROADCAST, 6) == 0)
				strlcpy(header, " Stations (unassociated)", sizeof(header));
			else
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
		}
		else
		{
			strlcpy(header, " Stations (all)", sizeof(header));
		}

		sta_box_top = view->show_ap ? (ap_height + 1) : 1;
		body_top = sta_box_top + 1;
		sta_box_left = 0;
		sta_box_width = state->cols;
		render_pane_box(sta_box_top, sta_box_left, sta_height, sta_box_width, header, state->focus == 1);
		render_station_header_row(body_top, 1, sta_box_width - 2);

		st_count = collect_visible_stations(view->st_1st, view, &st_rows);
		if (st_count == 0)
		{
			draw_padded_line(body_top + 1, 1, sta_box_width - 2, " No stations match the current filters.");
		}
		else
		{
			if ((size_t) state->sta_scroll > st_count - 1)
				state->sta_scroll = (int) (st_count - 1);
			if (state->sta_scroll < 0) state->sta_scroll = 0;
			if (state->focus == 1 && (size_t) state->sta_scroll >= st_count)
				state->sta_scroll = 0;

			st_start = (size_t) state->sta_scroll;
			for (i = 0; i < (size_t) state->sta_visible_rows && st_start + i < st_count;
				 ++i)
			{
				render_station_row(body_top + 1 + (int) i,
								   1,
								   sta_box_width - 2,
								   st_rows[st_start + i],
								   state,
								   view);
			}
		}
		draw_scrollbar(body_top + 1,
					   state->sta_visible_rows,
					   (int) st_count,
					   state->sta_scroll,
					   state->sta_visible_rows,
					   sta_box_width - 2,
					   state->focus == 1);
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
