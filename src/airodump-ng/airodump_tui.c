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

#include <ncurses.h>

#include "airodump_tui.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/compat.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/osdep/common.h"
#include "aircrack-ng/utf8/verifyssid.h"

extern int is_filtered_essid(const uint8_t * essid);

static long long station_age_seconds(const struct ST_info * st);
static int station_is_locally_administered(const struct ST_info * st);
static int station_band_value(const struct ST_info * st);
static const char * band_label_from_value(int band, int channel);
static void fill_inner_width(int y, int x, int width);
static void append_padded_column(char * line,
								 size_t line_size,
								 size_t * used,
								 const char * text,
								 int width,
								 int right_align,
								 int separator_spaces);
static void append_linef(char * line, size_t line_size, size_t * used, const char * fmt, ...);
static void format_header_message(char * out, size_t out_len, const char * message);

static void apply_mouse_mask(struct airodump_tui_state * state)
{
	if (state == NULL || !state->active) return;

	if (state->mouse_enabled)
	{
		mousemask(BUTTON1_PRESSED | BUTTON1_CLICKED | BUTTON1_DOUBLE_CLICKED | BUTTON2_CLICKED
					  | BUTTON4_CLICKED | BUTTON5_CLICKED,
				  NULL);
	}
	else
	{
		mousemask(0, NULL);
	}
}

enum station_header_column
{
	STATION_HEADER_BSSID = 0,
	STATION_HEADER_BAND,
	STATION_HEADER_STATION,
	STATION_HEADER_LA,
	STATION_HEADER_POWER,
	STATION_HEADER_RATE,
	STATION_HEADER_LOST,
	STATION_HEADER_FRAMES,
	STATION_HEADER_LAST_SEEN,
	STATION_HEADER_NOTES,
	STATION_HEADER_PROBES
};

struct station_header_field
{
	enum station_header_column column;
	int sort_by;
	const char * label;
	int width;
	int right_align;
	int separator_spaces;
};

struct station_header_span
{
	int sort_by;
	size_t start;
	size_t end;
	size_t label_start;
	size_t label_len;
};

struct ap_header_field
{
	int sort_by;
	const char * label;
	int width;
	int right_align;
	int separator_spaces;
};

struct ap_header_span
{
	int sort_by;
	size_t start;
	size_t end;
	size_t label_start;
	size_t label_len;
};

static const struct ap_header_field ap_header_fields[] = {
	{ SORT_BY_BSSID, "BSSID", 17, 0, 1 },
	{ SORT_BY_POWER, "PWR", 4, 1, 2 },
	{ SORT_BY_BEACON, "Beacons", 8, 1, 2 },
	{ SORT_BY_DATA, "#Data", 8, 1, 2 },
	{ SORT_BY_PRATE, "#/s", 4, 1, 2 },
	{ SORT_BY_CHAN, "CH", 3, 1, 2 },
	{ -1, "Band", 4, 0, 2 },
	{ SORT_BY_STAS, "STAs", 11, 1, 2 },
	{ SORT_BY_MBIT, "Mbit", 5, 1, 2 },
	{ SORT_BY_ENC, "ENC", 6, 0, 1 },
	{ SORT_BY_CIPHER, "CIPHER", 7, 0, 1 },
	{ SORT_BY_AUTH, "AUTH", 7, 0, 1 },
	{ SORT_BY_ESSID, "ESSID", 0, 0, 2 },
};

static const int ap_sort_cycle_fields[] = {
	SORT_BY_BSSID,
	SORT_BY_POWER,
	SORT_BY_BEACON,
	SORT_BY_DATA,
	SORT_BY_PRATE,
	SORT_BY_CHAN,
	SORT_BY_STAS,
	SORT_BY_MBIT,
	SORT_BY_ENC,
	SORT_BY_CIPHER,
	SORT_BY_AUTH,
	SORT_BY_ESSID,
};

static int bssid_palette_extended = 0;
static const short bssid_palette_fallback_fg_colors[24]
	= { COLOR_RED,
		COLOR_GREEN,
		COLOR_YELLOW,
		COLOR_BLUE,
		COLOR_MAGENTA,
		COLOR_CYAN,
		9,
		10,
		11,
		12,
		13,
		14,
		1,
		2,
		3,
		4,
		5,
		6,
		7,
		8,
		9,
		10,
		11,
		15 };
static const short bssid_palette_256_fg_colors[24]
	= { 196, 208, 226, 118, 46, 48, 51, 39, 33, 57, 93, 201,
		203, 190, 82, 37, 80, 75, 61, 99, 135, 168, 220, 123 };
static const short bssid_palette_rgb[24][3]
	= {
		{ 918, 424, 451 },
		{ 866, 494, 261 },
		{ 498, 851, 384 },
		{ 976, 686, 310 },
		{ 584, 402, 915 },
		{ 325, 741, 980 },
		{ 804, 631, 980 },
		{ 565, 882, 776 },
		{ 941, 443, 471 },
		{ 667, 851, 298 },
		{ 1000, 706, 329 },
		{ 349, 761, 1000 },
		{ 824, 651, 1000 },
		{ 584, 902, 796 },
		{ 930, 583, 530 },
		{ 742, 915, 291 },
		{ 324, 828, 707 },
		{ 415, 628, 1000 },
		{ 706, 554, 882 },
		{ 816, 502, 1000 },
		{ 1000, 690, 770 },
		{ 1000, 800, 320 },
		{ 741, 902, 651 },
		{ 630, 771, 920 },
	};

static size_t ap_header_label_offset(const struct ap_header_field * field)
{
	size_t offset = (size_t) field->separator_spaces;

	if (field->right_align)
	{
		size_t label_len = strlen(field->label);

		if (field->width > (int) label_len)
			offset += (size_t) field->width - label_len;
	}

	return (offset);
}

static size_t build_ap_header_line(char * line,
								   size_t line_size,
								   struct ap_header_span * spans,
								   size_t span_count,
								   const struct airodump_tui_view * view)
{
	size_t used = 1;
	size_t i;

	line[0] = ' ';
	for (i = 0; i < sizeof(ap_header_fields) / sizeof(ap_header_fields[0]); i++)
	{
		if (spans != NULL && i < span_count)
		{
			spans[i].sort_by = ap_header_fields[i].sort_by;
			spans[i].start = used;
			spans[i].label_start = used + ap_header_label_offset(&ap_header_fields[i]);
			spans[i].label_len = strlen(ap_header_fields[i].label);
		}
		append_padded_column(line,
							 line_size,
							 &used,
							 ap_header_fields[i].label,
							 ap_header_fields[i].width,
							 ap_header_fields[i].right_align,
							 ap_header_fields[i].separator_spaces);
		if (spans != NULL && i < span_count)
			spans[i].end = used;
	}
	if (view->show_uptime && used < line_size - 1)
		append_padded_column(line, line_size, &used, "UPTIME", 14, 0, 1);
	if (view->show_wps && used < line_size - 1)
		append_padded_column(line, line_size, &used, "WPS", 4, 0, 2);
	if (view->show_manufacturer && used < line_size - 1)
		append_padded_column(line, line_size, &used, "MANUFACTURER", 12, 0, 2);

	line[used] = '\0';
	return (used);
}

static const struct station_header_field station_header_fields[] = {
	{ STATION_HEADER_BSSID, STA_SORT_BY_BSSID, "BSSID", 17, 0, 1 },
	{ STATION_HEADER_STATION, STA_SORT_BY_STATION, "STATION", 17, 0, 2 },
	{ STATION_HEADER_BAND, STA_SORT_BY_BAND, "Band", 4, 0, 2 },
	{ STATION_HEADER_LA, STA_SORT_BY_LA, "LA", 2, 0, 2 },
	{ STATION_HEADER_POWER, STA_SORT_BY_POWER, "PWR", 4, 1, 2 },
	{ STATION_HEADER_RATE, STA_SORT_BY_RATE, "Rate", 7, 0, 2 },
	{ STATION_HEADER_LOST, STA_SORT_BY_LOST, "Lost", 4, 0, 2 },
	{ STATION_HEADER_FRAMES, STA_SORT_BY_FRAMES, "Frames", 8, 0, 2 },
	{ STATION_HEADER_LAST_SEEN, STA_SORT_BY_LAST_SEEN, "Last seen", 11, 0, 2 },
	{ STATION_HEADER_NOTES, STA_SORT_BY_NOTES, "Notes", 5, 0, 2 },
	{ STATION_HEADER_PROBES, STA_SORT_BY_PROBES, "Probes", 6, 0, 2 },
};

static const int station_sort_cycle_fields[] = {
	STA_SORT_BY_BSSID,
	STA_SORT_BY_STATION,
	STA_SORT_BY_BAND,
	STA_SORT_BY_LA,
	STA_SORT_BY_POWER,
	STA_SORT_BY_RATE,
	STA_SORT_BY_LOST,
	STA_SORT_BY_FRAMES,
	STA_SORT_BY_LAST_SEEN,
	STA_SORT_BY_NOTES,
	STA_SORT_BY_PROBES,
};

static size_t station_header_label_offset(const struct station_header_field * field)
{
	size_t offset = (size_t) field->separator_spaces;

	if (field->right_align)
	{
		size_t label_len = strlen(field->label);

		if (field->width > (int) label_len)
			offset += (size_t) field->width - label_len;
	}

	return (offset);
}

static int cycle_sort_field_from_list(const int * fields,
									  size_t field_count,
									  int sort_by,
									  int direction)
{
	size_t i;
	size_t start = 0;
	int found = 0;

	if (fields == NULL || field_count == 0) return (sort_by);
	if (direction == 0) direction = 1;

	for (i = 0; i < field_count; i++)
	{
		if (fields[i] == sort_by)
		{
			start = i;
			found = 1;
			break;
		}
	}

	if (!found)
		return ((direction > 0) ? fields[0] : fields[field_count - 1]);

	if (direction > 0)
		start = (start + 1) % field_count;
	else
		start = (start == 0) ? (field_count - 1) : (start - 1);

	return (fields[start]);
}

static size_t build_station_header_line(char * line,
										size_t line_size,
										struct station_header_span * spans,
										size_t span_count,
										const struct airodump_tui_view * view)
{
	(void) view;
	size_t used = 1;
	size_t i;

	line[0] = ' ';
	for (i = 0; i < sizeof(station_header_fields) / sizeof(station_header_fields[0]); i++)
	{
		if (spans != NULL && i < span_count)
		{
			spans[i].sort_by = station_header_fields[i].sort_by;
			spans[i].start = used;
			spans[i].label_start = used + station_header_label_offset(&station_header_fields[i]);
			spans[i].label_len = strlen(station_header_fields[i].label);
		}
		append_padded_column(line,
							 line_size,
							 &used,
							 station_header_fields[i].label,
							 station_header_fields[i].width,
							 station_header_fields[i].right_align,
							 station_header_fields[i].separator_spaces);
		if (spans != NULL && i < span_count)
			spans[i].end = used;
	}

	line[used] = '\0';
	return (used);
}

int airodump_tui_cycle_ap_sort_field(int sort_by, int direction)
{
	return (cycle_sort_field_from_list(ap_sort_cycle_fields,
									  sizeof(ap_sort_cycle_fields)
										/ sizeof(ap_sort_cycle_fields[0]),
									  sort_by,
									  direction));
}

int airodump_tui_cycle_station_sort_field(int sort_by, int direction)
{
	return (cycle_sort_field_from_list(station_sort_cycle_fields,
									  sizeof(station_sort_cycle_fields)
										/ sizeof(station_sort_cycle_fields[0]),
									  sort_by,
									  direction));
}

static void render_station_header_row(int y,
									 int x,
									 int width,
									 const struct airodump_tui_state * state,
									 const struct airodump_tui_view * view)
{
	char line[1024];
	struct station_header_span spans[sizeof(station_header_fields) / sizeof(station_header_fields[0])];
	size_t used;
	size_t i;

	used = build_station_header_line(line, sizeof(line), spans, sizeof(spans) / sizeof(spans[0]), view);
	if (width < 1) width = 1;
	if (width > (int) sizeof(line) - 1) width = (int) sizeof(line) - 1;
	line[width] = '\0';

	attron(A_DIM);
	mvaddnstr(y, x, line, width);
	for (i = 0; i < sizeof(spans) / sizeof(spans[0]); i++)
	{
		if (spans[i].sort_by != state->sta_sort_by)
			continue;
		if (spans[i].label_start < (size_t) width)
		{
			int highlight_len = (int) spans[i].label_len;
			int highlight_x = x + (int) spans[i].label_start;

			if (highlight_len > width - (int) spans[i].label_start)
				highlight_len = width - (int) spans[i].label_start;
			if (highlight_len > 0)
				mvchgat(y,
						highlight_x,
						highlight_len,
						A_BOLD,
						state->colors_enabled ? 7 : 0,
						NULL);
		}
		break;
	}
	fill_inner_width(y, x + (int) used, width - (int) used);
	attroff(A_DIM);
}

int airodump_tui_station_sort_field_from_mouse(const struct airodump_tui_state * state,
											   int x,
											   int y)
{
	char line[1024];
	struct station_header_span spans[sizeof(station_header_fields) / sizeof(station_header_fields[0])];
	struct airodump_tui_view view = { 0 };
	size_t used;
	size_t i;
	size_t inner_left;
	size_t inner_right;

	if (state == NULL) return (STA_SORT_BY_NOTHING);
	if (y != state->sta_box_top + 1) return (STA_SORT_BY_NOTHING);
	if (state->sta_box_width < 3) return (STA_SORT_BY_NOTHING);
	if (x < state->sta_box_left + 1 || x >= state->sta_box_left + state->sta_box_width - 1)
		return (STA_SORT_BY_NOTHING);

	used = build_station_header_line(line,
									 sizeof(line),
									 spans,
									 sizeof(spans) / sizeof(spans[0]),
									 &view);
	(void) used;

	inner_left = (size_t) (state->sta_box_left + 1);
	inner_right = (size_t) (state->sta_box_left + state->sta_box_width - 1);

	for (i = 0; i < sizeof(spans) / sizeof(spans[0]); i++)
	{
		size_t start = inner_left + spans[i].start;
		size_t end = inner_left + spans[i].end;

		if ((size_t) x >= start && (size_t) x < end && (size_t) x < inner_right)
			return (spans[i].sort_by);
	}

	return (STA_SORT_BY_NOTHING);
}

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
									   int sort_by,
									   int sort_inv,
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

	if (count > 1 && sort_by != SORT_BY_NOTHING)
	{
		size_t i;
		size_t j;

		for (i = 0; i < count - 1; i++)
		{
			size_t best = i;

			for (j = i + 1; j < count; j++)
			{
				const struct ST_info * lhs = rows[j];
				const struct ST_info * rhs = rows[best];
				int cmp = 0;

				switch (sort_by)
				{
					case STA_SORT_BY_BSSID:
						if (lhs->base != NULL && rhs->base != NULL)
							cmp = memcmp(lhs->base->bssid, rhs->base->bssid, 6);
						else if (lhs->base != NULL)
							cmp = 1;
						else if (rhs->base != NULL)
							cmp = -1;
						else
							cmp = 0;
						break;
					case STA_SORT_BY_STATION:
						cmp = memcmp(lhs->stmac, rhs->stmac, 6);
						break;
					case STA_SORT_BY_BAND:
						cmp = station_band_value(lhs) - station_band_value(rhs);
						break;
					case STA_SORT_BY_LA:
						cmp = station_is_locally_administered(lhs)
							  - station_is_locally_administered(rhs);
						break;
					case STA_SORT_BY_POWER:
						cmp = lhs->power - rhs->power;
						break;
					case STA_SORT_BY_RATE:
						cmp = MAX(lhs->rate_to, lhs->rate_from)
							  - MAX(rhs->rate_to, rhs->rate_from);
						break;
					case STA_SORT_BY_LOST:
						cmp = lhs->missed - rhs->missed;
						break;
					case STA_SORT_BY_FRAMES:
						cmp = (int) lhs->nb_pkt - (int) rhs->nb_pkt;
						break;
					case STA_SORT_BY_NOTES:
					{
						int lhs_note = (lhs->wpa.pmkid[0] != 0)
										   ? 2
										   : (lhs->wpa.state == 7 ? 1 : 0);
						int rhs_note = (rhs->wpa.pmkid[0] != 0)
										   ? 2
										   : (rhs->wpa.state == 7 ? 1 : 0);
						cmp = lhs_note - rhs_note;
						break;
					}
					case STA_SORT_BY_PROBES:
					{
						int lhs_count = 0;
						int rhs_count = 0;
						int k;

						for (k = 0; k < NB_PRB; k++)
						{
							if (lhs->ssid_length[k] > 0) lhs_count++;
							if (rhs->ssid_length[k] > 0) rhs_count++;
						}
						cmp = lhs_count - rhs_count;
						break;
					}
					case STA_SORT_BY_LAST_SEEN:
					{
						long long lhs_age = station_age_seconds(lhs);
						long long rhs_age = station_age_seconds(rhs);

						cmp = (lhs_age > rhs_age) ? 1 : (lhs_age < rhs_age ? -1 : 0);
						break;
					}
					default:
						cmp = lhs->tinit > rhs->tinit ? 1 : (lhs->tinit < rhs->tinit ? -1 : 0);
						break;
				}

				if (cmp == 0 && sort_by != SORT_BY_NOTHING)
					cmp = memcmp(lhs->stmac, rhs->stmac, 6);

				if ((cmp * sort_inv) < 0) best = j;
			}

			if (best != i)
			{
				struct ST_info * tmp = rows[i];
				rows[i] = rows[best];
				rows[best] = tmp;
			}
		}
	}

	*out_rows = rows;
	return (count);
}

static void security_std_string(char * out, size_t len, unsigned int security)
{
	if (out == NULL || len == 0) return;

	if (security & STD_WPA2)
	{
		if ((security & AUTH_SAE) && (security & AUTH_PSK))
			strlcpy(out, "WPA2/3", len);
		else if (security & AUTH_SAE)
			strlcpy(out, "WPA3", len);
		else if (security & AUTH_OWE)
			strlcpy(out, "OWE", len);
		else
			strlcpy(out, "WPA2", len);
		return;
	}
	if (security & STD_WPA)
		strlcpy(out, "WPA", len);
	else if (security & STD_WEP)
		strlcpy(out, "WEP", len);
	else if (security & STD_OPN)
		strlcpy(out, "OPN", len);
	else
		strlcpy(out, "", len);
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

	if ((security & AUTH_SAE) && (security & AUTH_PSK))
		strlcpy(out, "PSK+SAE", len);
	else if (security & AUTH_SAE)
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

static int is_broadcast_ap(const struct AP_info * ap)
{
	return (ap != NULL && memcmp(ap->bssid, BROADCAST, 6) == 0);
}

static char ap_row_marker(const struct AP_info * ap, int selected)
{
	if (selected)
		return ('>');
	if (ap != NULL && (ap->handshake_logged || ap->pmkid_logged))
		return ('*');
	return (' ');
}

#define BSSID_COLOR_PAIR_FIRST 8
#define BSSID_COLOR_BUCKETS 24
#define BSSID_COLOR_PAIR_LAST (BSSID_COLOR_PAIR_FIRST + BSSID_COLOR_BUCKETS - 1)

static int row_color_pair_from_bssid(const uint8_t * bssid)
{
	unsigned int mix;
	unsigned int bucket;
	int i;

	if (bssid == NULL || memcmp(bssid, BROADCAST, 6) == 0)
		return (7);

	mix = 2166136261u;
	for (i = 0; i < 6; i++)
	{
		mix ^= (unsigned int) bssid[i];
		mix *= 16777619u;
	}
	bucket = mix % BSSID_COLOR_BUCKETS;
	if (bssid_palette_extended)
		return ((int) bucket + BSSID_COLOR_PAIR_FIRST);
	return ((int) (bucket % 6) + 1);
}

static int ap_color_pair(const struct AP_info * ap)
{
	if (ap == NULL)
		return (7);
	return (row_color_pair_from_bssid(ap->bssid));
}

static int station_color_pair(const struct ST_info * st)
{
	if (st == NULL || st->base == NULL || is_broadcast_ap(st->base))
		return (7);
	return (ap_color_pair(st->base));
}

static int station_is_locally_administered(const struct ST_info * st)
{
	if (st == NULL) return (0);
	return (((st->stmac[0] & 0x02) != 0) ? 1 : 0);
}

static int station_band_value(const struct ST_info * st)
{
	if (st == NULL) return (-1);
	if (st->band != 0) return (st->band);
	if (st->base != NULL) return (st->base->band);
	return (-1);
}

static const char * band_label_from_value(int band, int channel)
{
	switch (band)
	{
		case 24:
			return ("2.4");
		case 5:
			return ("5");
		case 6:
			return ("6");
		default:
			if (channel > 14)
				return ("5");
			if (channel > 0)
				return ("2.4");
			return ("?");
	}
}

static long long station_age_seconds(const struct ST_info * st)
{
	time_t now;

	if (st == NULL) return (0);

	now = time(NULL);
	if (st->tlast > now)
		return (0);
	return ((long long) now - (long long) st->tlast);
}

static void format_station_last_seen(const struct ST_info * st,
									 char * out,
									 size_t out_len)
{
	long long age;

	if (st == NULL || out == NULL || out_len == 0)
		return;

	age = station_age_seconds(st);

	snprintf(out, out_len, "%02lld:%02lld", age / 60, age % 60);
}

static void format_bss_load_station_count(const struct AP_info * ap,
										  char * out,
										  size_t out_len)
{
	if (ap != NULL && ap->bss_load_station_count >= 0)
		snprintf(out, out_len, "%d", ap->bss_load_station_count);
	else
		strlcpy(out, "?", out_len);
}

static int visible_ap_station_count(const struct AP_info * ap,
									const struct airodump_tui_view * view)
{
	int count = 0;
	struct ST_info * st_cur;

	if (ap == NULL || view == NULL) return (0);

	st_cur = view->st_1st;
	while (st_cur != NULL)
	{
		if (time(NULL) - st_cur->tlast <= view->berlin)
		{
			if (memcmp(ap->bssid, BROADCAST, 6) == 0)
			{
				if (st_cur->base != NULL
					&& memcmp(st_cur->base->bssid, BROADCAST, 6) == 0)
					count++;
			}
			else if (st_cur->base == ap)
			{
				count++;
			}
		}
		st_cur = st_cur->next;
	}

	return (count);
}

static void format_ap_station_counts(char * out,
									 size_t out_len,
									 const struct AP_info * ap,
									 const struct airodump_tui_view * view)
{
	int visible_count;
	char advertised[16];
	char tmp[32];

	if (out == NULL || out_len == 0)
		return;

	visible_count = visible_ap_station_count(ap, view);
	format_bss_load_station_count(ap, advertised, sizeof(advertised));
	if (ap != NULL && ap->bss_load_station_count >= 0)
		snprintf(tmp, sizeof(tmp), "%d/%s", visible_count, advertised);
	else
		snprintf(tmp, sizeof(tmp), "%d/?", visible_count);

	strlcpy(out, tmp, out_len);
}

static void fill_inner_width(int y, int x, int width)
{
	if (width > 0)
		mvhline(y, x, ' ', width);
}

static void append_padded_column(char * line,
								 size_t line_size,
								 size_t * used,
								 const char * text,
								 int width,
								 int right_align,
								 int separator_spaces)
{
	char tmp[128];
	int written;
	int i;

	if (line == NULL || used == NULL || text == NULL || width < 0
		|| separator_spaces < 0)
		return;

	while (separator_spaces-- > 0 && *used < line_size - 1)
		line[(*used)++] = ' ';

	if (*used >= line_size - 1) return;

	written = snprintf(tmp,
					   sizeof(tmp),
					   right_align ? "%*s" : "%-*s",
					   width,
					   text);
	if (written < 0) return;
	if (written > (int) sizeof(tmp) - 1) written = (int) sizeof(tmp) - 1;

	for (i = 0; i < written && *used < line_size - 1; i++)
		line[(*used)++] = tmp[i];
	line[*used] = '\0';
}

static void append_linef(char * line, size_t line_size, size_t * used, const char * fmt, ...)
{
	va_list args;
	int written;

	if (line == NULL || used == NULL || fmt == NULL || line_size == 0)
		return;
	if (*used >= line_size - 1)
	{
		line[line_size - 1] = '\0';
		return;
	}

	va_start(args, fmt);
	written = vsnprintf(line + *used, line_size - *used, fmt, args);
	va_end(args);

	if (written < 0)
		return;
	if ((size_t) written >= line_size - *used)
		*used = line_size - 1;
	else
		*used += (size_t) written;
}

static void format_header_message(char * out, size_t out_len, const char * message)
{
	const char * p;
	size_t used = 0;

	if (out == NULL || out_len == 0) return;
	out[0] = '\0';
	if (message == NULL) return;

	p = message;
	while (isspace((unsigned char) *p))
		p++;
	if (p[0] == ']' && p[1] == '[')
		p += 2;
	while (isspace((unsigned char) *p))
		p++;

	while (*p != '\0' && used + 1 < out_len)
	{
		unsigned char ch = (unsigned char) *p++;

		if (ch == '\r' || ch == '\n' || ch == '\t')
			ch = ' ';
		if (iscntrl(ch))
			continue;
		out[used++] = (char) ch;
	}
	out[used] = '\0';
}

static void append_ap_core_columns(char * line,
								   size_t line_size,
								   size_t * used,
								   const char * bssid,
								   const char * power,
								   const char * beacons,
								   const char * data,
								   const char * rate,
								   const char * channel,
								   const char * band,
								   const char * stas,
								   const char * mbit,
								   const char * std,
								   const char * cipher,
								   const char * auth)
{
	append_padded_column(line, line_size, used, bssid, 17, 0, 1);
	append_padded_column(line, line_size, used, power, 4, 1, 2);
	append_padded_column(line, line_size, used, beacons, 8, 1, 2);
	append_padded_column(line, line_size, used, data, 8, 1, 2);
	append_padded_column(line, line_size, used, rate, 4, 1, 2);
	append_padded_column(line, line_size, used, channel, 3, 1, 2);
	append_padded_column(line, line_size, used, band, 4, 0, 2);
	append_padded_column(line, line_size, used, stas, 11, 1, 2);
	append_padded_column(line, line_size, used, mbit, 5, 1, 2);
	append_padded_column(line, line_size, used, std, 6, 0, 1);
	append_padded_column(line, line_size, used, cipher, 7, 0, 1);
	append_padded_column(line, line_size, used, auth, 7, 0, 1);
}

static void render_ap_header_row(int y,
								 int x,
								 int width,
								 const struct airodump_tui_state * state,
								 const struct airodump_tui_view * view)
{
	char line[1024];
	struct ap_header_span spans[sizeof(ap_header_fields) / sizeof(ap_header_fields[0])];
	size_t used = 1;
	size_t i;

	used = build_ap_header_line(line,
								sizeof(line),
								spans,
								sizeof(spans) / sizeof(spans[0]),
								view);

	if (width < 1) width = 1;
	if (width > (int) sizeof(line) - 1) width = (int) sizeof(line) - 1;
	line[width] = '\0';
		if (state != NULL)
		{
			attron(A_DIM);
			mvaddnstr(y, x, line, width);
			for (i = 0; i < sizeof(spans) / sizeof(spans[0]); i++)
			{
				if (spans[i].sort_by != view->sort_by)
					continue;
				if (spans[i].label_start < (size_t) width)
				{
				int highlight_len = (int) spans[i].label_len;
				int highlight_x = x + (int) spans[i].label_start;

				if (highlight_len > width - (int) spans[i].label_start)
					highlight_len = width - (int) spans[i].label_start;
				if (highlight_len > 0)
					mvchgat(y,
							highlight_x,
							highlight_len,
							A_BOLD,
							state->colors_enabled ? 7 : 0,
							NULL);
			}
			break;
		}
		attroff(A_DIM);
		}
		else
		{
			attron(A_BOLD);
			mvaddnstr(y, x, line, width);
			attroff(A_BOLD);
		}
	fill_inner_width(y, x + (int) used, width - (int) used);
}

int airodump_tui_ap_sort_field_from_mouse(const struct airodump_tui_state * state,
										   int x,
										   int y)
{
	char line[1024];
	struct ap_header_span spans[sizeof(ap_header_fields) / sizeof(ap_header_fields[0])];
	struct airodump_tui_view view = { 0 };
	size_t used;
	size_t i;
	size_t inner_left;
	size_t inner_right;

	if (state == NULL) return (SORT_BY_NOTHING);
	if (y != state->ap_box_top + 1) return (SORT_BY_NOTHING);
	if (state->ap_box_width < 3) return (SORT_BY_NOTHING);
	if (x < state->ap_box_left + 1 || x >= state->ap_box_left + state->ap_box_width - 1)
		return (SORT_BY_NOTHING);

	used = build_ap_header_line(line,
								sizeof(line),
								spans,
								sizeof(spans) / sizeof(spans[0]),
								&view);
	(void) used;

	inner_left = (size_t) (state->ap_box_left + 1);
	inner_right = (size_t) (state->ap_box_left + state->ap_box_width - 1);

	for (i = 0; i < sizeof(spans) / sizeof(spans[0]); i++)
	{
		size_t start = inner_left + spans[i].start;
		size_t end = inner_left + spans[i].end;

		if (spans[i].sort_by == SORT_BY_NOTHING)
			continue;
		if ((size_t) x >= start && (size_t) x < end && (size_t) x < inner_right)
			return (spans[i].sort_by);
	}

	return (SORT_BY_NOTHING);
}

static void render_message_style_begin(const struct airodump_tui_state * state,
									   enum airodump_tui_message_style style)
{
	if (state == NULL || !state->colors_enabled) return;

	switch (style)
	{
		case AIRODUMP_TUI_MESSAGE_STYLE_WARNING:
			attron(COLOR_PAIR(3));
			attron(A_BOLD);
			break;
		case AIRODUMP_TUI_MESSAGE_STYLE_SUCCESS:
			attron(COLOR_PAIR(2));
			break;
		default:
			break;
	}
}

static void render_message_style_end(const struct airodump_tui_state * state,
									 enum airodump_tui_message_style style)
{
	if (state == NULL || !state->colors_enabled) return;

	switch (style)
	{
		case AIRODUMP_TUI_MESSAGE_STYLE_WARNING:
			attroff(A_BOLD);
			attroff(COLOR_PAIR(3));
			break;
		case AIRODUMP_TUI_MESSAGE_STYLE_SUCCESS:
			attroff(COLOR_PAIR(2));
			break;
		default:
			break;
	}
}

static int render_message_row(int y,
							  int x,
							  int width,
							  int max_rows,
							  const struct airodump_tui_state * state,
							  const struct airodump_tui_message_entry * entry)
{
	char ts[32];
	struct tm * lt;
	int prefix_len;
	int rows_used = 0;
	const char * cursor;

	if (width < 1) width = 1;
	if (max_rows < 1) return (0);

	render_message_style_begin(state, entry->style);

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
		render_message_style_end(state, entry->style);
		return (1);
	}

	cursor = entry->text;
	while (*cursor != '\0' && rows_used < max_rows)
	{
		int available = width - prefix_len;
		int segment_len = 0;
		int last_space = -1;
		const char * segment = cursor;

		while (*segment != '\0' && isspace((unsigned char) *segment))
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
			if (segment[segment_len] == '\n' || segment[segment_len] == '\r'
				|| segment[segment_len] == '\t')
				break;
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
		while (*cursor != '\0' && isspace((unsigned char) *cursor))
			cursor++;
		rows_used++;
	}

	if (rows_used == 0)
	{
		mvaddnstr(y, x, ts, (int) strlen(ts));
		fill_inner_width(y, x + (int) strlen(ts), width - (int) strlen(ts));
		rows_used = 1;
	}

	render_message_style_end(state, entry->style);
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
	char bssid[32];
	char power[16];
	char beacons[16];
	char data[16];
	char rate[16];
	char channel[16];
	const char * band;
	char stas[16];
	char mbit[16];
	char cipher[32];
	char auth[32];
	char std[16];
	int pair;
	size_t used = 1;

	security_cipher_string(cipher, sizeof(cipher), ap->security);
	security_auth_string(auth, sizeof(auth), ap->security);
	security_std_string(std, sizeof(std), ap->security);
	format_ap_station_counts(stas, sizeof(stas), ap, view);
	pair = ap_color_pair(ap);
	snprintf(bssid,
			 sizeof(bssid),
			 "%02X:%02X:%02X:%02X:%02X:%02X",
			 ap->bssid[0],
			 ap->bssid[1],
			 ap->bssid[2],
			 ap->bssid[3],
			 ap->bssid[4],
			 ap->bssid[5]);
	snprintf(power, sizeof(power), "%d", ap->avg_power);
	snprintf(beacons, sizeof(beacons), "%lu", ap->nb_bcn);
	snprintf(data, sizeof(data), "%lu", ap->nb_data);
	snprintf(rate, sizeof(rate), "%d", ap->nb_dataps);
	snprintf(channel, sizeof(channel), "%d", ap->channel);
	snprintf(mbit, sizeof(mbit), "%d", ap->max_speed);
	band = band_label_from_value(ap->band, ap->channel);
	if (width < 2) width = 2;
	if (width > (int) sizeof(line) - 1) width = (int) sizeof(line) - 1;

	line[0] = ap_row_marker(ap, selected);
	append_ap_core_columns(line,
						   sizeof(line),
						   &used,
						   bssid,
						   power,
						   beacons,
						   data,
						   rate,
						   channel,
						   band,
						   stas,
						   mbit,
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
		snprintf(line + used, sizeof(line) - used, "  %s", ap->essid);
	}
	else if (memcmp(ap->bssid, BROADCAST, 6) == 0 && strlen(line) < sizeof(line) - 24)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, "  (unassociated clients)");
	}
	else if (strlen(line) < sizeof(line) - 16)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, "  <length:%d>",
				 ap->ssid_length);
	}

	line[width] = '\0';

	if (state->colors_enabled)
	{
		attron(COLOR_PAIR(pair));
		if (selected)
			attron(A_BOLD);
	}
	else if (selected)
	{
		attron(A_BOLD);
	}

	mvaddnstr(y, x, line, width);
	fill_inner_width(y, x + (int) strlen(line), width - (int) strlen(line));

	if (state->colors_enabled)
	{
		if (selected)
			attroff(A_BOLD);
		attroff(COLOR_PAIR(pair));
	}
	else if (selected)
	{
		attroff(A_BOLD);
	}
}

static size_t measure_ap_row_width(const struct AP_info * ap,
								   int selected,
								   const struct airodump_tui_view * view)
{
	char line[1024];
	char bssid[32];
	char power[16];
	char beacons[16];
	char data[16];
	char rate[16];
	char channel[16];
	const char * band;
	char stas[16];
	char mbit[16];
	char cipher[32];
	char auth[32];
	char std[16];
	size_t used = 1;

	security_cipher_string(cipher, sizeof(cipher), ap->security);
	security_auth_string(auth, sizeof(auth), ap->security);
	security_std_string(std, sizeof(std), ap->security);
	format_ap_station_counts(stas, sizeof(stas), ap, view);
	snprintf(bssid,
			 sizeof(bssid),
			 "%02X:%02X:%02X:%02X:%02X:%02X",
			 ap->bssid[0],
			 ap->bssid[1],
			 ap->bssid[2],
			 ap->bssid[3],
			 ap->bssid[4],
			 ap->bssid[5]);
	snprintf(power, sizeof(power), "%d", ap->avg_power);
	snprintf(beacons, sizeof(beacons), "%lu", ap->nb_bcn);
	snprintf(data, sizeof(data), "%lu", ap->nb_data);
	snprintf(rate, sizeof(rate), "%d", ap->nb_dataps);
	snprintf(channel, sizeof(channel), "%d", ap->channel);
	snprintf(mbit, sizeof(mbit), "%d", ap->max_speed);
	band = band_label_from_value(ap->band, ap->channel);

	line[0] = ap_row_marker(ap, selected);
	append_ap_core_columns(line,
						   sizeof(line),
						   &used,
						   bssid,
						   power,
						   beacons,
						   data,
						   rate,
						   channel,
						   band,
						   stas,
						   mbit,
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
		snprintf(line + used, sizeof(line) - used, "  %s", ap->essid);
	}
	else if (memcmp(ap->bssid, BROADCAST, 6) == 0 && strlen(line) < sizeof(line) - 24)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, "  (unassociated clients)");
	}
	else if (strlen(line) < sizeof(line) - 16)
	{
		size_t used = strlen(line);
		snprintf(line + used, sizeof(line) - used, "  <length:%d>",
				 ap->ssid_length);
	}

	return (strlen(line));
}

static size_t measure_ap_header_width(const struct airodump_tui_view * view)
{
	char line[1024];

	build_ap_header_line(line, sizeof(line), NULL, 0, view);

	return (strlen(line));
}

static int compute_ap_box_width(size_t ap_width, int cols, int msg_enabled, int needs_scrollbar)
{
	int ap_box_width;

	if (ap_width + 4 > (size_t) cols)
		ap_width = (cols > 4) ? (size_t) cols - 4 : 1;
	ap_box_width = (int) ap_width + 4;
	if (needs_scrollbar)
		ap_box_width++;
	if (msg_enabled && cols - ap_box_width < 24)
		ap_box_width = cols - 24;
	if (ap_box_width < 24)
		ap_box_width = 24;
	return (ap_box_width);
}

static void render_station_row(int y,
							   int x,
							   int width,
							   const struct ST_info * st,
							   const struct airodump_tui_state * state,
							   const struct airodump_tui_view * view)
{
	char line[1024];
	char bssid[32];
	const char * band;
	char station[32];
	char power[16];
	char rate[32];
	char lost[16];
	char frames[16];
	char last_seen[32];
	char notes[16];
	char probes[256];
	const char * assoc_label = NULL;
	const char * la_label = NULL;
	const char * cell_text;
	int pair;
	size_t used = 0;
	size_t probes_used = 0;
	int station_band;
	int station_channel;
	int i;

	probes[0] = '\0';
	for (i = 0; i < NB_PRB; i++)
	{
		if (st->probes[i][0] == '\0') continue;
		if (probes_used >= sizeof(probes) - 4) break;
		snprintf(probes + probes_used,
				 sizeof(probes) - probes_used,
				 "%s%s",
				 (probes_used > 0) ? "," : "",
				 st->probes[i]);
		probes_used = strlen(probes);
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
	snprintf(station,
			 sizeof(station),
			 "%02X:%02X:%02X:%02X:%02X:%02X",
			 st->stmac[0],
			 st->stmac[1],
			 st->stmac[2],
			 st->stmac[3],
			 st->stmac[4],
			 st->stmac[5]);
	format_station_last_seen(st, last_seen, sizeof(last_seen));
	station_band = st->band;
	station_channel = st->channel;
	if (station_band == 0 && st->base != NULL)
	{
		station_band = st->base->band;
		station_channel = st->base->channel;
	}
	band = band_label_from_value(station_band, station_channel);

	if (st->base != NULL && memcmp(st->base->bssid, BROADCAST, 6) == 0)
		assoc_label = "unassociated";
	if (station_is_locally_administered(st))
		la_label = "LA";
	pair = station_color_pair(st);

	snprintf(power, sizeof(power), "%d", st->power);
	snprintf(rate,
			 sizeof(rate),
			 "%2d/%-2d",
			 st->rate_to / 1000000,
			 st->rate_from / 1000000);
	snprintf(lost, sizeof(lost), "%d", st->missed);
	snprintf(frames, sizeof(frames), "%lu", st->nb_pkt);
	strlcpy(notes,
			(st->wpa.pmkid[0] != 0) ? "PMKID" : (st->wpa.state == 7 ? "EAPOL" : ""),
			sizeof(notes));

	line[0] = ' ';
	line[1] = '\0';
	used = 1;
	for (i = 0; i < (int) (sizeof(station_header_fields) / sizeof(station_header_fields[0])); i++)
	{
		switch (station_header_fields[i].column)
		{
			case STATION_HEADER_BSSID:
				cell_text = bssid;
				break;
			case STATION_HEADER_BAND:
				cell_text = band;
				break;
			case STATION_HEADER_STATION:
				cell_text = station;
				break;
			case STATION_HEADER_LA:
				cell_text = la_label != NULL ? la_label : "";
				break;
			case STATION_HEADER_POWER:
				cell_text = power;
				break;
			case STATION_HEADER_RATE:
				cell_text = rate;
				break;
			case STATION_HEADER_LOST:
				cell_text = lost;
				break;
			case STATION_HEADER_FRAMES:
				cell_text = frames;
				break;
			case STATION_HEADER_LAST_SEEN:
				cell_text = last_seen;
				break;
			case STATION_HEADER_NOTES:
				cell_text = notes;
				break;
			case STATION_HEADER_PROBES:
				cell_text = probes;
				break;
			default:
				cell_text = "";
				break;
		}
		append_padded_column(line,
							 sizeof(line),
							 &used,
							 cell_text,
							 station_header_fields[i].width,
							 station_header_fields[i].right_align,
							 station_header_fields[i].separator_spaces);
	}

	if (assoc_label != NULL && used < sizeof(line) - 1)
	{
		snprintf(line + used, sizeof(line) - used, " [%s]", assoc_label);
		used = strlen(line);
	}

	line[width] = '\0';
	if (state->colors_enabled)
	{
		attron(COLOR_PAIR(pair));
	}
	mvaddnstr(y, x, line, width);
	fill_inner_width(y, x + (int) strlen(line), width - (int) strlen(line));
	if (state->colors_enabled)
	{
		attroff(COLOR_PAIR(pair));
	}
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

static void render_count_tag(int top, int left, int width, size_t count)
{
	char buf[32];
	int len;
	int x;

	if (width < 4) return;

	snprintf(buf, sizeof(buf), " (%lu)", (unsigned long) count);
	len = (int) strlen(buf);
	x = left + width - 1 - len;
	if (x <= left) return;
	mvaddnstr(top, x, buf, len);
}

static void render_ascii_box(int top, int left, int height, int width, const char * title)
{
	int y;
	int inner_left;
	int inner_width;
	size_t title_len;
	char title_buf[160];

	if (top < 0 || left < 0 || height < 3 || width < 4) return;
	if (top + height > LINES) return;
	if (left + width > COLS) return;

	inner_left = left + 1;
	inner_width = width - 2;
	title_len = strlen(title);
	if (title_len > sizeof(title_buf) - 4) title_len = sizeof(title_buf) - 4;
	snprintf(title_buf, sizeof(title_buf), " %.*s ", (int) title_len, title);

	mvaddch(top, left, ACS_ULCORNER);
	mvhline(top, left + 1, ACS_HLINE, width - 2);
	mvaddch(top, left + width - 1, ACS_URCORNER);
	mvaddnstr(top, left + 2, title_buf, MIN((int) strlen(title_buf), width - 4));

	for (y = top + 1; y < top + height - 1; y++)
	{
		mvaddch(y, left, ACS_VLINE);
		mvaddch(y, left + width - 1, ACS_VLINE);
		mvhline(y, inner_left, ' ', inner_width);
	}

	mvaddch(top + height - 1, left, ACS_LLCORNER);
	mvhline(top + height - 1, left + 1, ACS_HLINE, width - 2);
	mvaddch(top + height - 1, left + width - 1, ACS_LRCORNER);
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
		append_linef(line, sizeof(line), &used, " CH");
		for (i = 0; i < view->num_cards; i++)
		{
			int frequency = view->frequency[i];
			int channel = getChannelFromFrequency(frequency);

			append_linef(line,
						 sizeof(line),
						 &used,
						 "%s%3d (%5d MHz)",
						 (i == 0) ? " " : ",",
						 channel > 0 ? channel : frequency,
						 frequency);
		}
	}
	else
	{
		append_linef(line, sizeof(line), &used, " CH");
		for (i = 0; i < view->num_cards; i++)
		{
			int frequency = view->frequency[i];

			if (frequency <= 0)
				frequency = getFrequencyFromChannel(view->channel[i]);
			append_linef(line,
						 sizeof(line),
						 &used,
						 "%s%3d (%5d MHz)",
						 (i == 0) ? " " : ",",
						 view->channel[i],
						 frequency);
		}
	}

	if (view->band_label != NULL)
		append_linef(line, sizeof(line), &used, " [Band: %s]", view->band_label);
	if (view->regdom_label != NULL)
		append_linef(line,
					 sizeof(line),
					 &used,
					 " [Regdom: %s%s]",
					 view->regdom_label,
					 view->regdom_self_managed ? "*" : "");

	if (view->batt != NULL && strcmp(view->batt, "]") != 0)
		append_linef(line, sizeof(line), &used, " %s", view->batt);
	if (view->elapsed_time != NULL)
		append_linef(line,
					 sizeof(line),
					 &used,
					 " [Elapsed: %s]",
					 view->elapsed_time);
	if (view->message != NULL && *view->message != '\0')
	{
		char header_message[32];

		format_header_message(header_message,
							  sizeof(header_message),
							  view->message);
		if (header_message[0] != '\0')
			append_linef(line,
						 sizeof(line),
						 &used,
						 " [Msg: %s]",
						 header_message);
	}

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
	const char * title_text;
	size_t title_len;

	if (cols < 3 || height < 2) return;
	title_text = title;
	while (*title_text == ' ')
		title_text++;
	title_len = strlen(title_text);
	if (active)
	{
		if (title_len > sizeof(line) - 6) title_len = sizeof(line) - 6;
		snprintf(line, sizeof(line), " [ %.*s ] ", (int) title_len, title_text);
	}
	else
	{
		if (title_len > sizeof(line) - 4) title_len = sizeof(line) - 4;
		snprintf(line, sizeof(line), " %.*s ", (int) title_len, title_text);
	}
	if (active) attron(A_BOLD);
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
	if (active) attroff(A_BOLD);
}

static void render_status_line(const struct airodump_tui_state * state,
							   const struct airodump_tui_view * view)
{
	(void) state;
	(void) view;
	char line[1024];
	int width;

	snprintf(line,
			 sizeof(line),
	"?:help | v:channels | b/B:band | l/r:lock/resume | d:deauth | s/S:sort | i:order | Tab/Left/Right:focus | Arrows/PgUp/PgDn/Home/End:scroll | q:quit");

	if (COLS < 1) return;
	width = MIN(COLS - 1, (int) sizeof(line) - 1);
	if (width > 0)
		mvaddnstr(LINES - 1, 0, line, MIN(width, (int) strlen(line)));
	clrtoeol();
}

static void render_help_overlay(void)
{
	static const char * lines[] = {
		"?: close help",
		"Tab / Left / Right: switch pane",
		"Arrow keys: scroll",
		"PgUp / PgDn: page scroll",
		"Home / End: jump to top/bottom",
		"Mouse wheel: scroll pane",
		"Mouse click header: sort column",
		"b / B: switch band next / previous",
		"l / r: lock channel / resume hopping",
		"d: deauth selected AP's stations",
		"s / S: cycle sort in active pane next / previous",
		"i: invert sort order",
		"g: set regulatory domain",
		"v: view channel availability",
		"t: tune channel",
		"w: write WPA snapshot",
		"c: clear AP filter",
		"o: toggle colors",
		"M: toggle mouse capture",
		"q: quit",
	};
	const int line_count = (int) (sizeof(lines) / sizeof(lines[0]));
	int max_len = 0;
	int i;
	int box_width;
	int box_height;
	int visible_count;
	int left;
	int top;

	for (i = 0; i < line_count; i++)
	{
		int len = (int) strlen(lines[i]);
		if (len > max_len) max_len = len;
	}

	box_width = max_len + 4;
	box_height = line_count + 4;
	if (box_width > COLS - 4) box_width = COLS - 4;
	if (box_height > LINES - 4) box_height = LINES - 4;
	if (box_width < 20 || box_height < 6) return;
	visible_count = MIN(line_count, box_height - 4);

	left = (COLS - box_width) / 2;
	top = (LINES - box_height) / 2;

	attron(A_REVERSE);
	for (i = 0; i < box_height; i++)
	{
		int y = top + i;
		if (y < 0 || y >= LINES) continue;
		mvhline(y, left, ' ', box_width);
	}
	attroff(A_REVERSE);

	render_ascii_box(top, left, box_height, box_width, " Help ");
	for (i = 0; i < visible_count; i++)
		mvaddnstr(top + 2 + i, left + 2, lines[i], box_width - 4);
}

static void render_channel_overlay(const struct airodump_tui_state * state,
								   const struct airodump_tui_view * view)
{
	int box_width;
	int box_height;
	int left;
	int top;
	int inner_width;
	int inner_height;
	int row_count;
	int columns;
	int col_width = 19;
	int i;
	char title[128];
	char regdom_title[64];

	if (view == NULL || view->channel_status == NULL
		|| view->channel_status_count == 0)
		return;

	box_width = MIN(COLS - 4, 82);
	box_height = MIN(LINES - 4, 24);
	if (box_width < 28 || box_height < 8) return;

	left = (COLS - box_width) / 2;
	top = (LINES - box_height) / 2;
	inner_width = box_width - 4;
	inner_height = box_height - 5;
	columns = MAX(1, inner_width / col_width);
	col_width = inner_width / columns;
	row_count = ((int) view->channel_status_count + columns - 1) / columns;
	if (row_count > inner_height) row_count = inner_height;

	attron(A_REVERSE);
	for (i = 0; i < box_height; i++)
	{
		int y = top + i;
		if (y < 0 || y >= LINES) continue;
		mvhline(y, left, ' ', box_width);
	}
	attroff(A_REVERSE);

	snprintf(regdom_title,
			 sizeof(regdom_title),
			 "Regdom: %s%s",
			 view->regdom_label != NULL ? view->regdom_label : "unknown",
			 view->regdom_self_managed ? " (device-managed)" : "");
	snprintf(title,
			 sizeof(title),
			 " Channels: %s | %s ",
			 view->band_label != NULL ? view->band_label : "band",
			 regdom_title);
	render_ascii_box(top, left, box_height, box_width, title);
	mvaddnstr(top + 1,
			  left + 2,
			  "green: ok  red: unavailable/refused  v/Esc: close",
			  box_width - 4);

	for (i = 0; i < (int) view->channel_status_count; i++)
	{
		const struct airodump_tui_channel_entry * entry = &view->channel_status[i];
		int col = i / row_count;
		int row = i % row_count;
		int y = top + 3 + row;
		int x = left + 2 + col * col_width;
		char line[32];

		if (col >= columns || y >= top + box_height - 1) continue;
		snprintf(line,
				 sizeof(line),
				 "ch %3d %5d %s",
				 entry->channel,
				 entry->frequency,
				 entry->status == AIRODUMP_TUI_CHANNEL_STATUS_REFUSED
					 ? "ref"
					 : entry->status == AIRODUMP_TUI_CHANNEL_STATUS_UNAVAILABLE
						   ? "no "
						   : entry->validated ? "ok " : "   ");
		if (entry->status == AIRODUMP_TUI_CHANNEL_STATUS_REFUSED
			|| entry->status == AIRODUMP_TUI_CHANNEL_STATUS_UNAVAILABLE)
		{
			if (state != NULL && state->colors_enabled)
				attron(COLOR_PAIR(1));
			else
				attron(A_BOLD);
		}
		else if (entry->validated && state != NULL && state->colors_enabled)
		{
			attron(COLOR_PAIR(2));
		}
		mvaddnstr(y, x, line, MIN(col_width - 1, (int) strlen(line)));
		if (entry->status == AIRODUMP_TUI_CHANNEL_STATUS_REFUSED
			|| entry->status == AIRODUMP_TUI_CHANNEL_STATUS_UNAVAILABLE)
		{
			if (state != NULL && state->colors_enabled)
				attroff(COLOR_PAIR(1));
			else
				attroff(A_BOLD);
		}
		else if (entry->validated && state != NULL && state->colors_enabled)
		{
			attroff(COLOR_PAIR(2));
		}
	}
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
	bssid_palette_extended = 0;
	if (can_change_color() && COLORS > 39 && COLOR_PAIRS > BSSID_COLOR_PAIR_LAST)
	{
		bssid_palette_extended = 1;
		for (i = 0; i < BSSID_COLOR_BUCKETS; i++)
		{
			short color_id = 16 + i;

			init_color(color_id,
					   bssid_palette_rgb[i][0],
					   bssid_palette_rgb[i][1],
					   bssid_palette_rgb[i][2]);
			init_pair(BSSID_COLOR_PAIR_FIRST + i, color_id, -1);
		}
	}
	else if (COLORS >= 256 && COLOR_PAIRS > BSSID_COLOR_PAIR_LAST)
	{
		bssid_palette_extended = 1;
		for (i = 0; i < BSSID_COLOR_BUCKETS; i++)
			init_pair(BSSID_COLOR_PAIR_FIRST + i, bssid_palette_256_fg_colors[i], -1);
	}
	else if (COLORS >= 16 && COLOR_PAIRS > BSSID_COLOR_PAIR_LAST)
	{
		bssid_palette_extended = 1;
		for (i = 0; i < 12; i++)
			init_pair(BSSID_COLOR_PAIR_FIRST + i, bssid_palette_fallback_fg_colors[i], -1);
	}
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
	return (1);
}

static void maybe_adjust_ghostty_term(void)
{
	const char * term = getenv("TERM");

	if (term != NULL && strcmp(term, "xterm-ghostty") == 0)
		setenv("TERM", "xterm-256color", 1);
}

int airodump_tui_start(struct airodump_tui_state * state)
{
	if (state == NULL) return (0);
	memset(state, 0, sizeof(*state));

	if (!airodump_tui_available())
	{
		return (0);
	}

	maybe_adjust_ghostty_term();

	if (initscr() == NULL)
	{
		return (0);
	}

	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	scrollok(stdscr, FALSE);
	set_escdelay(25);
	mouseinterval(0);
	curs_set(0);
	ensure_colors(state);
	state->active = 1;
	state->mouse_enabled = 1;
	state->sta_sort_by = SORT_BY_NOTHING;
	state->sta_sort_inv = 1;
	apply_mouse_mask(state);

	getmaxyx(stdscr, state->rows, state->cols);
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

void airodump_tui_set_mouse_enabled(struct airodump_tui_state * state, int enabled)
{
	if (state == NULL) return;
	state->mouse_enabled = enabled ? 1 : 0;
	apply_mouse_mask(state);
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
	state->ap_box_top = 0;
	state->ap_box_left = 0;
	state->ap_box_width = 0;
	state->ap_box_height = 0;
	state->msg_box_top = 0;
	state->msg_box_left = 0;
	state->msg_box_width = 0;
	state->msg_box_height = 0;
	state->sta_box_top = 0;
	state->sta_box_left = 0;
	state->sta_box_width = 0;
	state->sta_box_height = 0;

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

	ap_count = collect_visible_aps(view->ap_end, view, &ap_rows);
	if (view->show_ap && ap_count > 0)
	{
		size_t selected_index = 0;
		size_t ap_width = measure_ap_header_width(view);
		int ap_has_scrollbar;
		int ap_inner_width;

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
		ap_has_scrollbar = (ap_count > (size_t) state->ap_visible_rows);
		ap_box_width = compute_ap_box_width(ap_width, state->cols, msg_enabled, ap_has_scrollbar);
		ap_inner_width = ap_box_width - 2 - (ap_has_scrollbar ? 1 : 0);

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
		state->ap_box_top = ap_box_top;
		state->ap_box_left = ap_box_left;
		state->ap_box_width = ap_box_width;
		state->ap_box_height = ap_height;
		render_pane_box(ap_box_top, ap_box_left, ap_height, ap_box_width, " Access Points", state->focus == 0);
		render_ap_header_row(ap_box_top + 1, ap_box_left + 1, ap_inner_width, state, view);
		ap_start = (size_t) state->ap_scroll;
		for (i = 0; i < (size_t) state->ap_visible_rows && ap_start + i < ap_count;
			 ++i)
		{
			int selected = (ap_rows[ap_start + i] == selected_ap);
			render_ap_row((int) i + 3,
						  ap_box_left + 1,
						  ap_inner_width,
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
		render_count_tag(ap_box_top + ap_height - 1, ap_box_left, ap_box_width, ap_count);
	}
	else if (view->show_ap)
	{
		size_t ap_width = measure_ap_header_width(view);

		ap_box_top = 1;
		ap_height = MAX(4, ap_height);
		ap_box_left = 0;
		ap_box_width = compute_ap_box_width(ap_width, state->cols, msg_enabled, 0);
		render_pane_box(ap_box_top, ap_box_left, ap_height, ap_box_width, " Access Points", state->focus == 0);
		render_ap_header_row(ap_box_top + 1, ap_box_left + 1, ap_box_width - 2, state, view);
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
			state->msg_box_top = msg_box_top;
			state->msg_box_left = msg_box_left;
			state->msg_box_width = msg_box_width;
			state->msg_box_height = top_height;
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
													   state,
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
		state->sta_box_top = sta_box_top;
		state->sta_box_left = sta_box_left;
		state->sta_box_width = sta_box_width;
		state->sta_box_height = sta_height;
		render_pane_box(sta_box_top, sta_box_left, sta_height, sta_box_width, header, state->focus == 1);
		render_station_header_row(body_top, 1, sta_box_width - 2, state, view);

		st_count = collect_visible_stations(view->st_1st,
											view,
											state->sta_sort_by,
											state->sta_sort_inv,
											&st_rows);
		if (st_count == 0)
		{
			draw_padded_line(body_top + 1, 1, sta_box_width - 2, " No stations match the current filters.");
		}
		else
		{
			int max_scroll = MAX(0, (int) st_count - state->sta_visible_rows);

			if ((size_t) state->sta_scroll > st_count - 1)
				state->sta_scroll = (int) (st_count - 1);
			if (state->sta_scroll < 0) state->sta_scroll = 0;
			if (state->focus == 1 && (size_t) state->sta_scroll >= st_count)
				state->sta_scroll = 0;
			if (state->sta_scroll > max_scroll)
				state->sta_scroll = max_scroll;

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
		render_count_tag(sta_box_top + sta_height - 1, sta_box_left, sta_box_width, st_count);
	}

	render_status_line(state, view);
	render_header_line(view);
	if (state->help_visible)
		render_help_overlay();
	if (state->channel_overlay_visible)
		render_channel_overlay(state, view);
	wnoutrefresh(stdscr);
	doupdate();

	free(ap_rows);
	free(st_rows);
}
