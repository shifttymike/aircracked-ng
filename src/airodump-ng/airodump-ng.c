/*
 *  pcap-compatible 802.11 packet sniffer
 *
 *  Copyright (C) 2006-2022 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2004, 2005 Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>

#ifndef TIOCGWINSZ
#include <sys/termios.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#define _WITH_DPRINTF
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <termios.h>
#include <limits.h>

#include <sys/wait.h>

#ifdef HAVE_PCRE
#include <pcre.h>
#endif

#include "aircrack-ng/defs.h"
#include "aircrack-ng/version.h"
#include "aircrack-ng/support/pcap_local.h"
#include "aircrack-ng/ce-wep/uniqueiv.h"
#include "aircrack-ng/support/communications.h"
#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/osdep/channel.h"
#include "aircrack-ng/osdep/osdep.h"
#include "airodump-ng.h"
#include "dump_write.h"
#include "aircrack-ng/osdep/common.h"
#include "aircrack-ng/third-party/ieee80211.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/support/mcs_index_rates.h"
#include "aircrack-ng/utf8/verifyssid.h"
#include "airodump_tui.h"
#include "aircrack-ng/tui/console.h"
#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"

struct devices dev;

static const unsigned char llcnull[] = {0, 0, 0, 0};

static const char * OUI_PATHS[]
	= {"./airodump-ng-oui.txt",
	   "/etc/aircrack-ng/airodump-ng-oui.txt",
	   "/usr/local/etc/aircrack-ng/airodump-ng-oui.txt",
	   "/usr/share/aircrack-ng/airodump-ng-oui.txt",
	   "/var/lib/misc/oui.txt",
	   "/usr/share/misc/oui.txt",
	   "/usr/share/hwdata/oui.txt",
	   "/var/lib/ieee-data/oui.txt",
	   "/usr/share/ieee-data/oui.txt",
	   "/etc/manuf/oui.txt",
	   "/usr/share/wireshark/wireshark/manuf/oui.txt",
	   "/usr/share/wireshark/manuf/oui.txt",
	   NULL};

static int read_pkts = 0;
static int colors_enabled = 0;
static int force_legacy_ui = 0;

struct probe_log_entry
{
	struct probe_log_entry * next;
	time_t first_seen;
	time_t last_seen;
	unsigned long times_seen;
	uint8_t station_mac[6];
	size_t essid_len;
	unsigned char essid[ESSID_LENGTH + 1];
};

static struct probe_log_entry * probe_log_entries = NULL;

static int abg_chans[]
	= {1,   7,   13,  2,   8,   3,   14,  9,   4,   10,  5,   11,  6,
	   12,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,
	   60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116, 118,
	   120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149,
	   151, 153, 155, 157, 159, 161, 165, 169, 173, 0};

static int bg_chans[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0};

static int a_chans[]
	= {36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,
	   60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116,
	   118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142,
	   144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173, 0};

// Define an array of all ax channels - primary and secondary
int ax_all_chans[] 
	= {1,   2,   5,   9,   13,  17,  21,  25,  27,  29,  33,  37,
	   41,  45,  47,  49,  51,  53,  55,  57,  59,  61,  63,  65,
	   67,  69,  71,  73,  75,  77,  79,  81,  83,  85,  87,  89,
	   91,  93,  95,  97,  99,  101, 103, 105, 107, 109, 111, 113,
	   115, 117, 119, 121, 123, 125, 127, 129, 131, 133, 135, 137,
	   139, 141, 143, 145, 147, 149, 151, 153, 155, 157, 159, 161,
	   163, 165, 167, 169, 171, 173, 175, 177, 179, 181, 183, 185,
	   187, 189, 191, 193, 195, 197, 199, 201, 203, 205, 207, 209,
	   211, 213, 215, 217, 219, 221, 223, 225, 227, 229, 231, 233,
	   0};

// Define an array of the ax primary channels
static int ax_chans[] 
	= {1,   2,   5,   9,   13,  17,  21,  25,  29,  33,  37,  41,
	   45,  49,  53,  57,  61,  65,  69,  73,  77,  81,  85,  89,
	   93,  97,  101, 105, 109, 113, 117, 121, 125, 129, 133, 137,
	   141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185,
	   189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233, 0};

// Define a lookup table for channel to frequency mapping for bg
static const int channel_frequency_map_bg[] = {
    1, 2412,
    2, 2417,
    3, 2422,
    4, 2427,
    5, 2432,
    6, 2437,
    7, 2442,
    8, 2447,
    9, 2452,
    10, 2457,
    11, 2462,
    12, 2467,
    13, 2472,
    14, 2484,  // Channel 14 is 12 MHz away from channel 13
    -1, -1     // End marker
};

// Define a lookup table for channel to frequency mapping for a
static const int channel_frequency_map_a[] = {
    36, 5180,
    40, 5200,
    44, 5220,
    48, 5240,
    52, 5260,
    56, 5280,
    60, 5300,
    64, 5320,
    100, 5500,
    104, 5520,
    108, 5540,
    112, 5560,
    116, 5580,
    120, 5600,
    124, 5620,
    128, 5640,
    132, 5660,
    136, 5680,
    140, 5700,
    149, 5745,
    153, 5765,
    157, 5785,
    161, 5805,
    -1, -1     // End marker
};

// Define a lookup table for channel to frequency mapping for ax
static const int channel_frequency_map_ax[] = {
	1,   5955,
	2,   5935,
	5,   5975,
	9,   5995,
	13,  6015,
	17,  6035,
	21,  6055,
	25,  6075,
	29,  6095,
	33,  6115,
	37,  6135,
	41,  6155,
	45,  6175,
	49,  6195,
	53,  6215,
	57,  6235,
	61,  6255,
	65,  6275,
	69,  6295,
	73,  6315,
	77,  6335,
	81,  6355,
	85,  6375,
	89,  6395,
	93,  6415,
	97,  6435,
	101, 6455,
	105, 6475,
	109, 6495,
	113, 6515,
	117, 6535,
	121, 6555,
	125, 6575,
	129, 6595,
	133, 6615,
	137, 6635,
	141, 6655,
	145, 6675,
	149, 6695,
	153, 6715,
	157, 6735,
	161, 6755,
	165, 6775,
	169, 6795,
	173, 6815,
	177, 6835,
	181, 6855,
	185, 6875,
	189, 6895,
	193, 6915,
	197, 6935,
	201, 6955,
	205, 6975,
	209, 6995,
	213, 7015,
	217, 7035,
	221, 7055,
	225, 7075,
	229, 7095,
	233, 7115,
	-1,  -1     // End marker
};

// Function to convert network order 24-bit values into host-order
static uint32_t letoh24(const uint8_t *p) {
    // Manually construct the 24-bit value in little-endian order
    uint32_t val = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);

    // For little-endian systems, the value is already correct.
    // For big-endian systems, we need to rearrange the bytes.
    #if __BYTE_ORDER == __BIG_ENDIAN
    val = ((val & 0x0000FF) << 16) | (val & 0x00FF00) | ((val & 0xFF0000) >> 16);
    #endif

    return val;
}

#define MAX_FREQS 1000
#define MAX_FREQ_STR_LEN 6 // Each frequency is at most 5 digits plus a comma

// PPI Header Structure
struct ppi_hdr {
    uint8_t  pph_version;
    uint8_t  pph_flags;
    uint16_t pph_len;
    uint32_t pph_dlt;
};

// PPI Field Header Structure
struct ppi_fieldhdr {
    uint16_t pfh_type;
    uint16_t pfh_datalen;
};

// Constants for PPI
#define PPI_HDRLEN sizeof(struct ppi_hdr)
#define PPI_FIELD_HDRLEN sizeof(struct ppi_fieldhdr)
#define PPI_80211_COMMON 2
#define PPI_GEOTAG 30002

double last_coordinates[3] = {0.0, 0.0, 0.0};  // latitude, longitude, altitude

// Function to convert floating-point GPS data to a fixed-point representation
static uint32_t float_to_fixed37(float value) {
    return (uint32_t)((value + 180)* 10000000);
}

// Function to convert a float altitude value into a fixed-point representation
static uint32_t float_to_fixed64(float value) {
	return (uint32_t)((value + 180000.0) * 10000);
}

// Function to calculate the length of the ppi header
static size_t calculate_ppi_header_length(float gpsLat, float gpsLon, float gpsAlt) {
    size_t ppi_total_len = PPI_HDRLEN; // Base length of PPI header - 4 bytes

    // Add length of the 802.11-Common PPI data header
    ppi_total_len += PPI_FIELD_HDRLEN + 20; // 20 is the fixed length of the 802.11-Common data (total of 24)

    // Check if GPS data is available
    if (gpsLat != 0 && gpsLon != 0) {
        // Add length of the PPI-GEOLOCATION data fields
        ppi_total_len += PPI_FIELD_HDRLEN; // 4 bytes  
		ppi_total_len += 2 * sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t); // Geo Tag header [rev (1 byte), padding (1 byte), len (2 bytes), field mask (4 bytes)]
        ppi_total_len += 2 * sizeof(uint32_t);// Lat, Lon
        if (gpsAlt != 0) {
             ppi_total_len += sizeof(uint32_t); // Altitude
        }
    }

    return ppi_total_len;
}

static void write_ppi_headers_to_buffer(uint8_t *buffer, 
                              uint64_t tsfTimer, uint16_t dataRate, 
                              uint16_t freq, int8_t rssi, int8_t noise, 
                              float gpsLat, float gpsLon, float gpsAlt) {
    struct ppi_hdr pph;
    struct ppi_fieldhdr pfh;
    uint32_t gpsFieldMask = 0;
    uint32_t fixedLat, fixedLon, fixedAlt;
    uint16_t geoFhLen;
    uint8_t geoTagRev = 2;
    uint8_t geoTagPad = 0;
    uint16_t geoTagHeaderLen;
    size_t offset = 0;

    // Initialize PPI header
    pph.pph_version = 0;
    pph.pph_flags = 0;
    pph.pph_len = PPI_HDRLEN;  // Will be updated later
    pph.pph_dlt = 105;  // Example DLT value for 802.11

    // Write PPI header
    memcpy(buffer + offset, &pph, PPI_HDRLEN);
    offset += PPI_HDRLEN;

    // Prepare 802.11-Common PPI field header
    pfh.pfh_type = PPI_80211_COMMON;
    pfh.pfh_datalen = 20;
    memcpy(buffer + offset, &pfh, PPI_FIELD_HDRLEN);
    offset += PPI_FIELD_HDRLEN;

    // Write 802.11-Common data fields
    memcpy(buffer + offset, &tsfTimer, sizeof(tsfTimer));
    offset += sizeof(tsfTimer);
    uint16_t flags = 0;
    memcpy(buffer + offset, &flags, sizeof(flags));
    offset += sizeof(flags);
    memcpy(buffer + offset, &dataRate, sizeof(dataRate));
    offset += sizeof(dataRate);
    memcpy(buffer + offset, &freq, sizeof(freq));
    offset += sizeof(freq);
    uint16_t channelFlags = 0;
    memcpy(buffer + offset, &channelFlags, sizeof(channelFlags));
    offset += sizeof(channelFlags);
    uint8_t fhssHopset = 0, fhssPattern = 0;
    memcpy(buffer + offset, &fhssHopset, sizeof(fhssHopset));
    offset += sizeof(fhssHopset);
    memcpy(buffer + offset, &fhssPattern, sizeof(fhssPattern));
    offset += sizeof(fhssPattern);
    memcpy(buffer + offset, &rssi, sizeof(rssi));
    offset += sizeof(rssi);
    memcpy(buffer + offset, &noise, sizeof(noise));
    offset += sizeof(noise);

    // If GPS data is available, write Geolocation field
    if (gpsLat != 0 && gpsLon != 0) {
        fixedLat = float_to_fixed37(gpsLat);
        fixedLon = float_to_fixed37(gpsLon);
        gpsFieldMask |= 0b00000110; // Lat/Long fields present
        if (gpsAlt != 0) {
            fixedAlt = float_to_fixed64(gpsAlt);
            gpsFieldMask |= 0b00001000; // Altitude field present
        }

        pfh.pfh_type = PPI_GEOTAG;
        geoFhLen = 8 + sizeof(fixedLat) + sizeof(fixedLon);
        if (gpsAlt != 0) geoFhLen += sizeof(fixedAlt);
        pfh.pfh_datalen = geoFhLen;

        memcpy(buffer + offset, &pfh, PPI_FIELD_HDRLEN);
        offset += PPI_FIELD_HDRLEN;
        memcpy(buffer + offset, &geoTagRev, sizeof(geoTagRev));
        offset += sizeof(geoTagRev);
        memcpy(buffer + offset, &geoTagPad, sizeof(geoTagPad));
        offset += sizeof(geoTagPad);
        geoTagHeaderLen = 8 + sizeof(fixedLat) + sizeof(fixedLon);
        if (gpsAlt != 0) geoTagHeaderLen += sizeof(fixedAlt);
        memcpy(buffer + offset, &geoTagHeaderLen, sizeof(geoTagHeaderLen));
        offset += sizeof(geoTagHeaderLen);
        memcpy(buffer + offset, &gpsFieldMask, sizeof(gpsFieldMask));
        offset += sizeof(gpsFieldMask);
        memcpy(buffer + offset, &fixedLat, sizeof(fixedLat));
        offset += sizeof(fixedLat);
        memcpy(buffer + offset, &fixedLon, sizeof(fixedLon));
        offset += sizeof(fixedLon);
        if (gpsAlt != 0) {
            memcpy(buffer + offset, &fixedAlt, sizeof(fixedAlt));
            offset += sizeof(fixedAlt);
        }
    }

    // Update total length in PPI header
    ((struct ppi_hdr *)buffer)->pph_len = (uint16_t)offset;
}


static void write_ppi_headers(FILE *file, uint64_t tsfTimer, uint16_t dataRate, uint16_t freq, int8_t rssi, int8_t noise, float gpsLat, float gpsLon, float gpsAlt) {
    uint8_t *common_buffer = NULL, *gps_buffer = NULL;
    size_t common_size = 0, gps_size = 0, total_size = 0;

    // **1. Build 802.11-Common Field Header and Data**
    common_size = PPI_FIELD_HDRLEN + 20; // Header size + 802.11-Common data size
    common_buffer = malloc(common_size);
    if (!common_buffer) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    // Fill 802.11-Common Field Header
    struct ppi_fieldhdr common_fh = {
        .pfh_type = htole16(PPI_80211_COMMON),
        .pfh_datalen = htole16(20)
    };
    memcpy(common_buffer, &common_fh, PPI_FIELD_HDRLEN);

    // Fill 802.11-Common Data
    size_t offset = PPI_FIELD_HDRLEN;
    uint64_t le_tsfTimer = htole64(tsfTimer);
    memcpy(common_buffer + offset, &le_tsfTimer, sizeof(le_tsfTimer));
    offset += sizeof(le_tsfTimer);

    uint16_t flags = 0;
    memcpy(common_buffer + offset, &flags, sizeof(flags));
    offset += sizeof(flags);

    uint16_t le_dataRate = htole16(dataRate);
    memcpy(common_buffer + offset, &le_dataRate, sizeof(le_dataRate));
    offset += sizeof(le_dataRate);

    uint16_t le_freq = htole16(freq);
    memcpy(common_buffer + offset, &le_freq, sizeof(le_freq));
    offset += sizeof(le_freq);

    uint16_t channelFlags = 0;
    memcpy(common_buffer + offset, &channelFlags, sizeof(channelFlags));
    offset += sizeof(channelFlags);

    uint8_t fhssHopset = 0, fhssPattern = 0;
    memcpy(common_buffer + offset, &fhssHopset, sizeof(fhssHopset));
    offset += sizeof(fhssHopset);
    memcpy(common_buffer + offset, &fhssPattern, sizeof(fhssPattern));
    offset += sizeof(fhssPattern);

    memcpy(common_buffer + offset, &rssi, sizeof(rssi));
    offset += sizeof(rssi);
    memcpy(common_buffer + offset, &noise, sizeof(noise));
    offset += sizeof(noise);

    // **2. Optionally Build GPS Data**
    if (gpsLat != 0 && gpsLon != 0) {
        uint32_t gpsFieldMask = 0;
        uint32_t fixedLat = float_to_fixed37(gpsLat);
        uint32_t fixedLon = float_to_fixed37(gpsLon);
        gpsFieldMask |= 0b00000110; // Lat/Long fields present

        uint32_t fixedAlt = 0;
        if (gpsAlt != 0) {
            fixedAlt = float_to_fixed64(gpsAlt);
            gpsFieldMask |= 0b00001000; // Altitude field present
        }

        gps_size = PPI_FIELD_HDRLEN + 8 + sizeof(fixedLat) + sizeof(fixedLon) + (gpsAlt != 0 ? sizeof(fixedAlt) : 0);
        gps_buffer = malloc(gps_size);
        if (!gps_buffer) {
            perror("malloc failed");
            free(common_buffer);
            exit(EXIT_FAILURE);
        }

        struct ppi_fieldhdr gps_fh = {
            .pfh_type = htole16(PPI_GEOTAG),
            .pfh_datalen = htole16(gps_size - PPI_FIELD_HDRLEN)
        };
        memcpy(gps_buffer, &gps_fh, PPI_FIELD_HDRLEN);

        offset = PPI_FIELD_HDRLEN;
        uint8_t geoTagRev = 2, geoTagPad = 0;
        uint16_t geoTagHeaderLen = htole16(8 + sizeof(fixedLat) + sizeof(fixedLon) + (gpsAlt != 0 ? sizeof(fixedAlt) : 0));
        uint32_t le_gpsFieldMask = htole32(gpsFieldMask);

        memcpy(gps_buffer + offset, &geoTagRev, sizeof(geoTagRev));
        offset += sizeof(geoTagRev);
        memcpy(gps_buffer + offset, &geoTagPad, sizeof(geoTagPad));
        offset += sizeof(geoTagPad);
        memcpy(gps_buffer + offset, &geoTagHeaderLen, sizeof(geoTagHeaderLen));
        offset += sizeof(geoTagHeaderLen);
        memcpy(gps_buffer + offset, &le_gpsFieldMask, sizeof(le_gpsFieldMask));
        offset += sizeof(le_gpsFieldMask);

        uint32_t le_fixedLat = htole32(fixedLat);
        memcpy(gps_buffer + offset, &le_fixedLat, sizeof(le_fixedLat));
        offset += sizeof(le_fixedLat);

        uint32_t le_fixedLon = htole32(fixedLon);
        memcpy(gps_buffer + offset, &le_fixedLon, sizeof(le_fixedLon));
        offset += sizeof(le_fixedLon);

        if (gpsAlt != 0) {
            uint32_t le_fixedAlt = htole32(fixedAlt);
            memcpy(gps_buffer + offset, &le_fixedAlt, sizeof(le_fixedAlt));
            offset += sizeof(le_fixedAlt);
        }
    }

    // **3. Calculate Total Size**
    total_size = PPI_HDRLEN + common_size + gps_size;

    // **4. Build PPI Header**
    struct ppi_hdr pph = {
        .pph_version = 0,
        .pph_flags = 0,
        .pph_len = htole16(total_size),
        .pph_dlt = htole32(105) // Example DLT value for 802.11
    };

    // **5. Write Components to File**
    fwrite(&pph, 1, PPI_HDRLEN, file);
    fwrite(common_buffer, 1, common_size, file);
    if (gps_buffer) {
        fwrite(gps_buffer, 1, gps_size, file);
    }

    fflush(file);

    // Free buffers
    free(common_buffer);
    free(gps_buffer);
}

static int * frequencies;

static volatile int quitting = 0;
static volatile time_t quitting_event_ts = 0;
static volatile int deauth_launching = 0;
static volatile time_t deauth_event_ts = 0;
static volatile pid_t hopper_pid = -1;
static int hopper_pipe_ready = 0;
static volatile sig_atomic_t hopper_event_pending = 0;
static volatile sig_atomic_t hopper_reject_seq = 0;
static volatile sig_atomic_t hopper_reject_count = 0;
static volatile sig_atomic_t hopper_reject_total = 0;
static volatile sig_atomic_t hopper_reject_card = -1;
static volatile sig_atomic_t hopper_reject_value = 0;
static volatile sig_atomic_t hopper_reject_is_freq = 0;
static volatile sig_atomic_t regdom_refresh_pending = 0;
static volatile sig_atomic_t hopper_refused_values[AIRODUMP_TUI_MAX_CHANNEL_STATUS];
static volatile sig_atomic_t hopper_refused_is_freq[AIRODUMP_TUI_MAX_CHANNEL_STATUS];
static volatile sig_atomic_t hopper_refused_count = 0;
static pid_t main_pid = -1;
static int channel_entry_active = 0;
static char channel_entry_buf[8];
static char channel_entry_prompt[128];
static size_t channel_entry_len = 0;
static char cached_regdom[16];
static struct wif ** g_wi = NULL;
static int use_ncurses_tui = 0;
static volatile sig_atomic_t tui_resize_pending = 0;
static struct airodump_tui_state tui_state;
#define BAND_MODE_BG 0
#define BAND_MODE_A 1
#define BAND_MODE_AX 2
#define BAND_MODE_CUSTOM 3
#define AIRODUMP_TUI_MESSAGE_HISTORY 256
static struct airodump_tui_message_entry tui_message_history[AIRODUMP_TUI_MESSAGE_HISTORY];
static size_t tui_message_history_count = 0;
static char tui_message_history_last[512];
static void dump_sort(void);
static int ap_sort_is_live(int sort_by);
static void dump_print(int ws_row, int ws_col, int if_num);
static char *
get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2);
int is_filtered_essid(const uint8_t * essid);
static int launch_deauth(void);
static int resume_hopper(void);
static int getchancount(int valid);
static int getfreqcount(int valid);
static void channel_hopper(struct wif * wi[], int if_num, int chan_count, pid_t parent);
static void frequency_hopper(struct wif * wi[], int if_num, int chan_count, pid_t parent);
static int channel_to_frequency_ax(int channel);
static int channel_to_frequency(int channel);
static int frequency_to_channel(int frequency);
static int band_from_frequency_or_channel(int frequency, int channel);
static int band_from_rx_info(const struct rx_info * ri, int channel);
static int channel_is_valid_for_band(int channel);
static int park_on_channel(int channel);
static void begin_channel_entry(void);
static void cancel_channel_entry(const char * message);
static int apply_channel_entry(void);
static int lock_selected_ap_channel(void);
static int infer_band_mode(void);
static int band_support_mask_for_interface(const char * ifname);
static int band_support_mask_for_cards(struct wif * wi[], int num_cards);
static int supported_band_mode_mask(void);
static int band_mode_is_supported(int band_mode);
static int next_supported_band_mode(int current_band_mode, int direction);
static void stop_hopper(void);
static int switch_band(int direction);
static const char * band_mode_label(int band_mode);
static int handle_keycode(int keycode);
static void render_output(void);
static void render_output_view(int record_message_history);
static void restore_terminal(void);
static void record_tui_message_history(void);
static void append_tui_message_history(const char * message, time_t timestamp);
static void append_tui_message_history_now(const char * message);
static int normalize_tui_message(const char * message, char * out, size_t out_len);
static void reset_hopper_reject_state(void);
static void update_hopper_reject_message(void);
static void process_hopper_event(int card, int value);
static void record_hopper_refused_target(int value, int is_freq);
static int hopper_target_refused(int value, int is_freq);
static size_t get_allowed_ax_frequencies(int * freqs, size_t max_freqs);
static int ax_frequency_in_hopper_list(int frequency);
static size_t build_channel_status_entries(struct airodump_tui_channel_entry * entries,
										   size_t max_entries);
static void set_hopper_pipe_nonblocking(void);
static int ap_security_std_rank(unsigned int security);
static int ap_security_cipher_rank(unsigned int security);
static int ap_security_auth_rank(unsigned int security);
static int ap_station_count_rank(const struct AP_info * ap);
static int ap_essid_compare(const struct AP_info * lhs, const struct AP_info * rhs);
static void set_channel_entry_prompt(void);
static int write_wpa_snapshot(void);
static int get_active_phy_index(void);
static int get_kernel_regdom(char * out, size_t out_len);
static void cache_kernel_regdom(const char * regdom);
static const char * get_cached_regdom(int force_refresh);
static void set_message_follow_latest(int follow_latest);
static int tui_message_pane_visible(void);
static void set_tui_focus(int focus);
static int handle_mouse_event(void);
static struct AP_info * pick_ap_from_mouse(int x, int y);
static void set_selected_ap(struct AP_info * ap,
							int selection_direction);
static void cycle_tui_focus(int direction);
static char * csv_escape_field(const unsigned char * input, size_t len);
static void format_probe_timestamp(char * out, size_t out_len, time_t ts);
static struct probe_log_entry * find_probe_log_entry(const unsigned char * probe,
													 size_t len);
static void log_distinct_probe_essid(const struct ST_info * st_cur,
									 const unsigned char * probe,
									 size_t len);
static void free_probe_log_entries(void);
static int deauth_mfp_guard(struct AP_info * ap_cur);
static int deauth_is_unassociated_ap(const struct AP_info * ap_cur);
static void deauth_refuse_with_message(const char * reason);

/* bunch of global stuff */
struct communication_options opt;
static struct local_options
{
	struct AP_info *ap_1st, *ap_end;
	struct ST_info *st_1st, *st_end;
	struct NA_info * na_1st;
	struct oui * manufList;

	unsigned char prev_bssid[6];
	char ** f_essid;
	int f_essid_count;
#ifdef HAVE_PCRE
	pcre * f_essid_regex;
#endif
	char * dump_prefix;
	char * keyout;

	char * batt; /* Battery string       */
	int channel[MAX_CARDS]; /* current channel #    */
	int frequency[MAX_CARDS]; /* current frequency #    */
	int ch_pipe[2]; /* current channel pipe */
	int cd_pipe[2]; /* current card pipe    */
	int gc_pipe[2]; /* gps coordinates pipe */
	float gps_loc[8]; /* gps coordinates      */
	int save_gps; /* keep gps file flag   */
	int gps_valid_interval; /* how many seconds until we consider the GPS data invalid if we dont get new data */

	int * channels;
	int singlechan; /* channel hopping set 1*/
	int singlefreq; /* frequency hopping: 1 */
	int chswitch; /* switching method     */
	unsigned int f_encrypt; /* encryption filter    */
	int update_s; /* update delay in sec  */

	volatile int do_exit; /* interrupt flag       */
	struct winsize ws; /* console window size  */

	char * elapsed_time; /* capture time			*/

	int one_beacon; /* Record only 1 beacon?*/

	int * own_channels; /* custom channel list  */
	int * own_frequencies; /* custom frequency list  */
	int band_mode; /* current band selection */
	int band_support_mask; /* cached supported bands across cards (-1 = unknown) */

	int asso_client; /* only show associated clients */

	unsigned char wpa_bssid[6]; /* the wpa handshake bssid   */
	char message[512];
	char decloak;

	char is_berlin; /* is the switch --berlin set? */
	int numaps; /* number of APs on the current list */
	int maxnumaps; /* maximum nubers of APs on the list */
	int maxaps; /* number of all APs found */
	int berlin; /* number of seconds it takes in berlin to fill the whole screen
				   with APs*/
	/*
	 * The name for this option may look quite strange, here is the story behind
	 * it:
	 * During the CCC2007, 10 august 2007, we (hirte, Mister_X) went to visit
	 * Berlin
	 * and couldn't resist to turn on airodump-ng to see how much access point
	 * we can
	 * get during the trip from Finowfurt to Berlin. When we were in Berlin, the
	 * number
	 * of AP increase really fast, so fast that it couldn't fit in a screen,
	 * even rotated;
	 * the list was really huge (we have a picture of that). The 2 minutes
	 * timeout
	 * (if the last packet seen is higher than 2 minutes, the AP isn't shown
	 * anymore)
	 * wasn't enough, so we decided to create a new option to change that
	 * timeout.
	 * We implemented this option in the highest tower (TV Tower) of Berlin,
	 * eating an ice.
	 */

	int show_ap;
	int show_sta;
	int show_ack;
	int hide_known;

	int hopfreq;

	char * s_iface; /* source interface to read from */
	FILE * f_cap_in;
	struct pcap_file_header pfh_in;
	int detect_anomaly; /* Detect WIPS protecting WEP in action */

	char * freqstring;
	int freqoption;
	int chanoption;
	int active_scan_sim; /* simulates an active scan, sending probe requests */

	/* Airodump-ng start time: for kismet netxml file */
	char * airodump_start_time;

	pthread_t input_tid;
	pthread_t gps_tid;
	int sort_by;
	int sort_inv;
	int start_print_ap;
	int start_print_sta;
	struct AP_info * p_selected_ap;
	enum
	{
		selection_direction_down,
		selection_direction_up,
		selection_direction_no
	} en_selection_direction;
	int num_cards;
	int do_pause;
	int do_sort_always;

	pthread_mutex_t mx_print; /* lock write access to ap LL   */
	pthread_mutex_t mx_sort; /* lock write access to ap LL   */

	unsigned char selected_bssid[6]; /* bssid that is selected */

	u_int maxsize_essid_seen;
	int show_manufacturer;
	int show_uptime;
	int file_write_interval;
	u_int maxsize_wps_seen;
	int show_wps;
	struct tm gps_time; /* the timestamp from the gps data */
#ifdef CONFIG_LIBNL
	unsigned int htval;
#endif
	int background_mode;

	unsigned long min_pkts;

	int relative_time; /* read PCAP in psuedo-real-time */
	int scan_11ax;
	int ppi;
	double coordinates[2];
	int target;
	char ip[INET_ADDRSTRLEN];
	int port;
	int tcp_sock_fd;
	int ax_bw;
	int c_seg0;
	int c_seg1;


} lopt;

static int normalize_tui_message(const char * message, char * out, size_t out_len)
{
	size_t used = 0;
	int pending_space = 0;

	if (message == NULL || out == NULL || out_len == 0) return (0);

	while (*message != '\0'
		   && (*message == ']' || *message == '[' || isspace((unsigned char) *message)))
	{
		message++;
	}
	while (*message != '\0' && used + 1 < out_len)
	{
		if (isspace((unsigned char) *message))
		{
			pending_space = (used > 0);
		}
		else
		{
			if (pending_space && used + 1 < out_len)
				out[used++] = ' ';
			out[used++] = *message;
			pending_space = 0;
		}
		message++;
	}
	while (used > 0 && isspace((unsigned char) out[used - 1]))
		used--;
	out[used] = '\0';
	return (used > 0);
}

static enum airodump_tui_message_style message_style_from_text(const char * message)
{
	if (message == NULL) return (AIRODUMP_TUI_MESSAGE_STYLE_DEFAULT);

	if (strstr(message, "Selected AP requires MFP") != NULL
		|| strstr(message, "Selected AP advertises optional MFP") != NULL)
	{
		return (AIRODUMP_TUI_MESSAGE_STYLE_WARNING);
	}

	if (strstr(message, "PMKID found:") != NULL
		|| strstr(message, "WPA handshake:") != NULL)
	{
		return (AIRODUMP_TUI_MESSAGE_STYLE_SUCCESS);
	}

	return (AIRODUMP_TUI_MESSAGE_STYLE_DEFAULT);
}

/* targeting globals*/
#define MAX_TARGETS 100
unsigned char targets[MAX_TARGETS][6]; // Array to store MAC addresses
uint8_t wildcard_nibbles[MAX_TARGETS][12];
int num_targets = 0; // Number of MAC addresses stored

static int convertMACToBytesWithWildcards(const char *mac_str, uint8_t *mac_bytes, uint8_t *nibble_mask) {
    if (strlen(mac_str) != 17) return -1;

    for (int i = 0; i < 6; i++) {
        char c1 = mac_str[i * 3];
        char c2 = mac_str[i * 3 + 1];

        if (i < 5 && mac_str[i * 3 + 2] != ':') return -1;

        uint8_t high_nibble, low_nibble;

        // High nibble
        if (c1 == '?') {
            high_nibble = 0;
            nibble_mask[i * 2] = 1;
        } else if (isxdigit(c1)) {
            high_nibble = (uint8_t)(isdigit(c1) ? c1 - '0' : (tolower(c1) - 'a' + 10));
            nibble_mask[i * 2] = 0;
        } else return -1;

        // Low nibble
        if (c2 == '?') {
            low_nibble = 0;
            nibble_mask[i * 2 + 1] = 1;
        } else if (isxdigit(c2)) {
            low_nibble = (uint8_t)(isdigit(c2) ? c2 - '0' : (tolower(c2) - 'a' + 10));
            nibble_mask[i * 2 + 1] = 0;
        } else return -1;

        mac_bytes[i] = (high_nibble << 4) | low_nibble;
    }

    return 0;
}


// Function to parse a file for MAC addresses
static int parseMACAddressFile(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) return -1;

    char line[64]; // enough for safety
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0'; // Trim newline

        if (num_targets >= MAX_TARGETS) break;

        if (convertMACToBytesWithWildcards(line, targets[num_targets], wildcard_nibbles[num_targets]) == 0) {
            num_targets++;
        }
    }

    fclose(file);
    return 0;
}

static int isTargetMAC(uint8_t *mac_address) {
    for (int i = 0; i < num_targets; i++) {
        int matched = 1;
        for (int j = 0; j < 6; j++) {
            uint8_t target_byte = targets[i][j];
            uint8_t target_high = (target_byte & 0xF0) >> 4;
            uint8_t target_low = target_byte & 0x0F;

            uint8_t mac_high = (mac_address[j] & 0xF0) >> 4;
            uint8_t mac_low = mac_address[j] & 0x0F;

            if (!wildcard_nibbles[i][j * 2] && mac_high != target_high) {
                matched = 0; break;
            }
            if (!wildcard_nibbles[i][j * 2 + 1] && mac_low != target_low) {
                matched = 0; break;
            }
        }
        if (matched) return 1;
    }
    return 0;
}

// Function to validate and store IP and port from user input
int validate_ip_port(const char *input) {
    if (!input) return 0;  // Null check

    char temp[INET_ADDRSTRLEN + 6];  // Buffer for IP:PORT (max "255.255.255.255:65535")
    strncpy(temp, input, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    char *ip_part = strtok(temp, ":,");  // Extract IP (supports ":" or "," as delimiter)
    char *port_part = strtok(NULL, ":,");  // Extract Port

    // Ensure both parts exist
    if (!ip_part || !port_part) {
        fprintf(stderr, "Invalid format! Use IP:PORT or IP,PORT\n");
        return 0;
    }

    // Validate IP address
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip_part, &(sa.sin_addr)) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_part);
        return 0;
    }

    // Validate Port
    char *endptr;
    long port = strtol(port_part, &endptr, 10);
    if (*endptr != '\0' || port < 1 || port > 65535) {
        fprintf(stderr, "Invalid port number: %s\n", port_part);
        return 0;
    }

    // Store valid values in lopt (existing structure)
    strncpy(lopt.ip, ip_part, INET_ADDRSTRLEN - 1);
    lopt.ip[INET_ADDRSTRLEN - 1] = '\0';  // Ensure null-termination
    lopt.port = (int)port;

    return 1;  // Success
}

// Function to start a TCP server and return the accepted client socket
int start_tcp_server(const char *ip, int port) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;
    char spinner[] = "|/-\\";  // Spinner animation characters
    int spin_index = 0;

    // Create the server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Allow immediate reuse of the address and port
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Convert IP address
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid IP address");
        close(server_fd);
        return -1;
    }

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return -1;
    }

    // Listen for connections
    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        close(server_fd);
        return -1;
    }

    printf("TCP server listening on %s:%d\n", ip, port);

    // Display a rotating status message on the same line
    printf("Waiting for a client to connect... ");

    fflush(stdout);  // Ensure output is printed immediately

    // Accept loop with EINTR handling and rotating animation
    while (1) {
        printf("\rWaiting for a client to connect... %c", spinner[spin_index]);
        fflush(stdout);
        spin_index = (spin_index + 1) % 4;  // Rotate through spinner characters
        usleep(200000);  // Sleep for 200ms to slow down animation

        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;  // Retry accept() if interrupted
            }
            perror("\nAccept failed");
            close(server_fd);
            return -1;
        }
        break;  // Exit loop when accept() succeeds
    }

    printf("\rClient connected!                           \n");  // Clear line
    close(server_fd);  // Close the listening socket (we only need the client socket)
    return client_fd;
}


static void resetSelection(void)
{
	lopt.sort_by = SORT_BY_NOTHING;
	lopt.sort_inv = 1;

	lopt.relative_time = 0;
	lopt.start_print_ap = 1;
	lopt.start_print_sta = 1;
	lopt.p_selected_ap = NULL;
	lopt.en_selection_direction = selection_direction_no;
	lopt.do_pause = 0;
	lopt.do_sort_always = 0;
	memset(lopt.selected_bssid, '\x00', 6);
}

static void format_mac(char * out, size_t out_len, const uint8_t mac[6])
{
	snprintf(out,
			 out_len,
			 "%02X:%02X:%02X:%02X:%02X:%02X",
			 mac[0],
			 mac[1],
			 mac[2],
			 mac[3],
			 mac[4],
			 mac[5]);
}

static int launch_deauth(void)
{
	struct AP_info * ap_cur;
	struct ST_info * st_cur;
	struct wif * wi[MAX_CARDS];
	char apmac[18];
	char stmac[18];
	char wlan_if[64];
	const char * ifname;
	int station_count = 0;
	int i;
	int new_channel;
	int new_frequency;
	int status;
	int launched_any = 0;

	if (lopt.p_selected_ap == NULL)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ no AP selected");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	ap_cur = lopt.p_selected_ap;
	format_mac(apmac, sizeof(apmac), ap_cur->bssid);

	if (deauth_is_unassociated_ap(ap_cur))
	{
		deauth_refuse_with_message("Selected AP is the unassociated-client entry");
		return (0);
	}

	if (g_wi == NULL || g_wi[0] == NULL)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ no wireless interface available");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	ifname = wi_get_ifname(g_wi[0]);
	if (ifname == NULL)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ unable to resolve wireless interface name");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	strlcpy(wlan_if, ifname, sizeof(wlan_if));

	for (i = 0; i < MAX_CARDS; i++)
	{
		wi[i] = NULL;
	}
	for (i = 0; i < lopt.num_cards; i++)
		wi[i] = g_wi[i];

	new_channel = ap_cur->channel;
	new_frequency = 0;
	if (hopper_pid > 0)
		stop_hopper();

	if (lopt.freqoption)
	{
		new_frequency = channel_to_frequency(ap_cur->channel);
		if (new_frequency <= 0)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ unable to map AP channel to frequency");
			append_tui_message_history_now(lopt.message);
			goto restore_state;
		}
	}

	lopt.singlechan = 0;
	lopt.singlefreq = 0;

	for (i = 0; i < lopt.num_cards; i++)
	{
		int ret = 0;

		if (lopt.freqoption)
		{
#ifdef CONFIG_LIBNL
			ret = wi_set_freq_ax(wi[i],
								 new_frequency,
								 lopt.ax_bw,
								 lopt.c_seg0,
								 lopt.c_seg1);
#else
			ret = wi_set_freq(wi[i], new_frequency);
#endif
			if (ret != 0)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to tune %s to AP frequency",
						 wi_get_ifname(wi[i]));
				append_tui_message_history_now(lopt.message);
				goto restore_state;
			}
			lopt.frequency[i] = new_frequency;
		}
		else
		{
#ifdef CONFIG_LIBNL
			ret = wi_set_ht_channel(wi[i], new_channel, lopt.htval);
#else
			ret = wi_set_channel(wi[i], new_channel);
#endif
			if (ret != 0)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to tune %s to AP channel",
						 wi_get_ifname(wi[i]));
				append_tui_message_history_now(lopt.message);
				goto restore_state;
			}
			lopt.channel[i] = new_channel;
		}
	}

	st_cur = lopt.st_1st;
	while (st_cur != NULL)
	{
		if (time(NULL) - st_cur->tlast <= lopt.berlin && st_cur->base == ap_cur)
		{
			station_count++;
		}
		st_cur = st_cur->next;
	}

	if (station_count == 0)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ No stations for selected AP");
		append_tui_message_history_now(lopt.message);
		goto restore_state;
	}

	snprintf(lopt.message,
			 sizeof(lopt.message),
			 "][ running aireplay-ng for %d station%s",
			 station_count,
			 (station_count == 1) ? "" : "s");
	append_tui_message_history_now(lopt.message);
	if (!use_ncurses_tui)
	{
		printf("%s\n", lopt.message);
		fflush(stdout);
	}
	launched_any = 1;

	st_cur = lopt.st_1st;
	while (st_cur != NULL)
	{
		if (time(NULL) - st_cur->tlast <= lopt.berlin && st_cur->base == ap_cur)
		{
			int pipefd[2];
			pid_t child_pid;

			format_mac(stmac, sizeof(stmac), st_cur->stmac);
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ aireplay-ng %s",
					 stmac);
			append_tui_message_history_now(lopt.message);
			if (!use_ncurses_tui)
			{
				printf("%s\n", lopt.message);
				fflush(stdout);
			}

			if (pipe(pipefd) < 0)
			{
				perror("pipe");
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to capture aireplay-ng output");
				append_tui_message_history_now(lopt.message);
				goto restore_state;
			}

			child_pid = fork();
			if (child_pid < 0)
			{
				perror("fork");
				close(pipefd[0]);
				close(pipefd[1]);
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to launch aireplay-ng");
				append_tui_message_history_now(lopt.message);
				goto restore_state;
			}

			if (child_pid == 0)
			{
				int null_fd;

				setsid();
				close(pipefd[0]);
				null_fd = open("/dev/null", O_RDONLY);
				if (null_fd >= 0)
				{
					if (dup2(null_fd, STDIN_FILENO) < 0)
					{
						perror("dup2");
						_exit(127);
					}
					close(null_fd);
				}
				if (dup2(pipefd[1], STDOUT_FILENO) < 0
					|| dup2(pipefd[1], STDERR_FILENO) < 0)
				{
					perror("dup2");
					_exit(127);
				}
				close(pipefd[1]);
				execlp("aireplay-ng",
					   "aireplay-ng",
					   "-0",
					   "5",
					   "-a",
					   apmac,
					   "-c",
					   stmac,
					   wlan_if,
					   (char *) NULL);
				perror("aireplay-ng");
				_exit(127);
			}

			close(pipefd[1]);
			{
				char read_buf[512];
				char line_buf[1024];
				size_t line_len = 0;
				ssize_t nread;

				while ((nread = read(pipefd[0], read_buf, sizeof(read_buf))) > 0)
				{
					ssize_t i;

					for (i = 0; i < nread; i++)
					{
						unsigned char ch = (unsigned char) read_buf[i];

						if (ch == '\n' || ch == '\r')
						{
							if (line_len > 0)
							{
								line_buf[line_len] = '\0';
								if (use_ncurses_tui)
								{
									append_tui_message_history_now(line_buf);
								}
								else
								{
									printf("%s\n", line_buf);
									fflush(stdout);
								}
								line_len = 0;
							}
							continue;
						}

						if (line_len + 1 >= sizeof(line_buf))
						{
							line_buf[line_len] = '\0';
							if (use_ncurses_tui)
							{
								append_tui_message_history_now(line_buf);
							}
							else
							{
								printf("%s\n", line_buf);
								fflush(stdout);
							}
							line_len = 0;
						}

						line_buf[line_len++] = (char) ch;
					}
				}

				if (line_len > 0)
				{
					line_buf[line_len] = '\0';
					if (use_ncurses_tui)
					{
						append_tui_message_history_now(line_buf);
					}
					else
					{
						printf("%s\n", line_buf);
						fflush(stdout);
					}
				}
			}

			close(pipefd[0]);
			while (waitpid(child_pid, &status, 0) < 0)
			{
				if (errno != EINTR)
					break;
			}
		}
		st_cur = st_cur->next;
	}

restore_state:
	snprintf(lopt.message,
			 sizeof(lopt.message),
			 "][ deauth complete");
	append_tui_message_history_now(lopt.message);
	if (!use_ncurses_tui)
	{
		printf("%s\n", lopt.message);
		fflush(stdout);
	}

	lopt.singlechan = lopt.freqoption ? 0 : 1;
	lopt.singlefreq = lopt.freqoption ? 1 : 0;

	return (launched_any);
}

static void color_off(void)
{
	struct AP_info * ap_cur;

	colors_enabled = 0;
	ap_cur = lopt.ap_1st;
	while (ap_cur != NULL)
	{
		ap_cur->marked = 0;
		ap_cur->marked_color = 1;
		ap_cur = ap_cur->next;
	}

	textcolor_normal();
	textcolor_fg(TEXT_WHITE);
}

static void color_on(void)
{
	struct AP_info * ap_cur;
	struct ST_info * st_cur;
	int color = 2;

	color_off();
	colors_enabled = 1;

	ap_cur = lopt.ap_end;

	while (ap_cur != NULL)
	{
		if (ap_cur->nb_pkt < lopt.min_pkts
			|| time(NULL) - ap_cur->tlast > lopt.berlin)
		{
			ap_cur = ap_cur->prev;
			continue;
		}

		if (ap_cur->security != 0 && lopt.f_encrypt != 0
			&& ((ap_cur->security & lopt.f_encrypt) == 0))
		{
			ap_cur = ap_cur->prev;
			continue;
		}

		// Don't filter unassociated clients by ESSID
		if (memcmp(ap_cur->bssid, BROADCAST, 6) != 0
			&& is_filtered_essid(ap_cur->essid))
		{
			ap_cur = ap_cur->prev;
			continue;
		}

		st_cur = lopt.st_end;

		while (st_cur != NULL)
		{
			if (st_cur->base != ap_cur
				|| time(NULL) - st_cur->tlast > lopt.berlin)
			{
				st_cur = st_cur->prev;
				continue;
			}

			if (!memcmp(ap_cur->bssid, BROADCAST, 6) && lopt.asso_client)
			{
				st_cur = st_cur->prev;
				continue;
			}

			if (color > TEXT_MAX_COLOR) color++;

			if (!ap_cur->marked)
			{
				ap_cur->marked = 1;
				if (!memcmp(ap_cur->bssid, BROADCAST, 6))
					ap_cur->marked_color = 1;
				else
					ap_cur->marked_color = color++;
			}

			st_cur = st_cur->prev;
		}

		ap_cur = ap_cur->prev;
	}
}

static THREAD_ENTRY(input_thread)
{
	UNUSED_PARAM(arg);

	while (lopt.do_exit == 0)
	{
		int keycode = mygetch();

		if (handle_keycode(keycode) && !use_ncurses_tui && lopt.do_exit == 0
			&& !lopt.do_pause)
		{
			ALLEGE(pthread_mutex_lock(&(lopt.mx_print)) == 0);
			render_output();
			ALLEGE(pthread_mutex_unlock(&(lopt.mx_print)) == 0);
		}
	}

	return (NULL);
}

static FILE * open_oui_file(void)
{
	int i;
	FILE * fp = NULL;

	for (i = 0; OUI_PATHS[i] != NULL; i++)
	{
		fp = fopen(OUI_PATHS[i], "r");
		if (fp != NULL)
		{
			break;
		}
	}

	return (fp);
}

static struct oui * load_oui_file(void)
{
	FILE * fp;
	char * manuf;
	char buffer[BUFSIZ];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	struct oui *oui_ptr = NULL, *oui_head = NULL;

	fp = open_oui_file();
	if (!fp)
	{
		return (NULL);
	}

	memset(buffer, 0x00, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer), fp) != NULL)
	{
		if (!(strstr(buffer, "(hex)"))) continue;

		memset(a, 0x00, sizeof(a));
		memset(b, 0x00, sizeof(b));
		memset(c, 0x00, sizeof(c));
		// Remove leading/trailing whitespaces.
		trim(buffer);
		if (sscanf(buffer, "%2c-%2c-%2c", (char *) a, (char *) b, (char *) c)
			== 3)
		{
			if (oui_ptr == NULL)
			{
				if (!(oui_ptr = (struct oui *) malloc(sizeof(struct oui))))
				{
					fclose(fp);
					perror("malloc failed");
					return (NULL);
				}
			}
			else
			{
				if (!(oui_ptr->next
					  = (struct oui *) malloc(sizeof(struct oui))))
				{
					fclose(fp);
					perror("malloc failed");

					while (oui_head != NULL)
					{
						oui_ptr = oui_head->next;
						free(oui_head);
						oui_head = oui_ptr;
					}
					return (NULL);
				}
				oui_ptr = oui_ptr->next;
			}
			memset(oui_ptr->id, 0x00, sizeof(oui_ptr->id));
			memset(oui_ptr->manuf, 0x00, sizeof(oui_ptr->manuf));
			snprintf(oui_ptr->id,
					 sizeof(oui_ptr->id),
					 "%c%c:%c%c:%c%c",
					 a[0],
					 a[1],
					 b[0],
					 b[1],
					 c[0],
					 c[1]);
			manuf = get_manufacturer_from_string(buffer);
			if (manuf != NULL)
			{
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "%s", manuf);
				free(manuf);
			}
			else
			{
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "Unknown");
			}
			if (oui_head == NULL) oui_head = oui_ptr;
			oui_ptr->next = NULL;
		}
	}

	fclose(fp);
	return (oui_head);
}

static const char usage[] =

	"\n"
	"  %s - (C) 2006-2022 Thomas d\'Otreppe\n"
	"  https://www.aircrack-ng.org\n"
	"\n"
	"  usage: airodump-ng <options> <interface>[,<interface>,...]\n"
	"\n"
	"  Options:\n"
	"      --ivs                 : Save only captured IVs\n"
	"      --gpsd                : Use GPSd\n"
	"      -w / --write <prefix> : Dump file prefix\n"
	"      -w                    : same as --write \n"
	"      -p / --ppi            : Create pcap PPI headers with radiotap/gps tags\n"
	"      -y / --coords         : Provide fixed coordinates for ppi geo tags. Use with --ppi option.\n"
	"      --beacons             : Record all beacons in dump file\n"
	"      --update       <secs> : Display update delay in seconds\n"
	"      --showack             : Prints ack/cts/rts statistics\n"
	"      -h                    : Hides known stations for --showack\n"
	"      -f            <msecs> : Time in ms between hopping channels\n"
	"      --berlin       <secs> : Time before removing the AP/client\n"
	"                              from the screen when no more packets\n"
	"                              are received (Default: 120 seconds)\n"
	"      -r             <file> : Read packets from that file\n"
	"      -T                    : While reading packets from a file,\n"
	"                              simulate the arrival rate of them\n"
	"                              as if they were \"live\".\n"
	"      -x            <msecs> : Active Scanning Simulation\n"
	"      --manufacturer        : Display manufacturer from IEEE OUI list\n"
	"      --uptime              : Display AP Uptime from Beacon Timestamp\n"
	"      --wps                 : Display WPS information (if any)\n"
	"      -o / --output-format\n"
	"                  <formats> : Output format. Possible values:\n"
	"                              pcap, ivs, csv, gps, kismet, netxml, "
	"logcsv\n"
	"      -P / --probes         : Log probe sightings to a live CSV file\n"
	"      --legacy-ui           : Force the legacy text UI instead of ncurses\n"
	"      --ignore-negative-one : Removes the message that says\n"
	"                              fixed channel <interface>: -1\n"
	"      --write-interval\n"
	"                  <seconds> : Output file(s) write interval in seconds\n"
	"      --background <enable> : Override background detection.\n"
	"      -n              <int> : Minimum AP packets recv'd before\n"
	"                              for displaying it\n"
	"      -z / --target \n"
	"              <mac or file> : Enter a target mac to highlight\n"
	"                              or pass a file of newline separated macs\n"
	"      -V / --tcp-server\n"
	"              <ip:port>     : Enter an IPv4 listen address and \n"
	"              <ip,port>       valid port number. Requires -w / --write option\n"
	"\n"
	"  Filter options:\n"
	"      --encrypt     <suite> : Filter APs by cipher suite\n"
	"      --netmask   <netmask> : Filter APs by mask\n"
	"      --bssid       <bssid> : Filter APs by BSSID\n"
	"      --essid       <essid> : Filter APs by ESSID\n"
#ifdef HAVE_PCRE
	"      --essid-regex <regex> : Filter APs by ESSID using a regular\n"
	"                              expression\n"
#endif
	"      -a                    : Filter unassociated clients\n"
	"\n"
	"  By default, airodump-ng hops on 2.4GHz channels.\n"
	"  You can make it capture on other/specific channel(s) by using:\n"
	"      --ht20                : Set channel to HT20 (802.11n)\n"
	"      --ht40-               : Set channel to HT40- (802.11n)\n"
	"      --ht40+               : Set channel to HT40+ (802.11n)\n"
	"      --ax40                : Set channel to 40 MHz bandwidth (802.11ax)\n"
	"      --ax80                : Set channel to 80 MHz bandwidth (802.11ax)\n"
	"      --ax80+               : Set channel to 80+80 MHz bandwidth (802.11ax)\n"
	"      --ax160               : Set channel to 160 MHz bandwidth (802.11ax)\n"
	"      --cseg0        <freq> : Center Segement 0 - for 40, 80, and 160 MHz secondary frequencies (802.11ax)\n"
	"      --cseg1        <freq> : Center Segement 1 - for 80+80 MHz secondary frequency (802.11ax)\n"
	"      -X / --80211ax        : Capture on 802.11ax 6E channels. Must use -c with 6E channel number\n"
	"      -c / --channel <chs>  : Capture on specific channels\n"
	"      -b / --band   <abgx>  : Band on which airodump-ng should hop\n"
	"      -C     <frequencies>  : Uses these frequencies in MHz to hop\n"
	"      --cswitch  <method>   : Set channel switching method\n"
	"                    0       : FIFO (default)\n"
	"                    1       : Round Robin\n"
	"                    2       : Hop on last\n"
	"      -s                    : same as --cswitch\n"
	"\n"
	"  Interactive TUI controls:\n"
	"      ? / F1                : Show or close help\n"
	"      Tab / Left / Right    : Switch focused pane\n"
	"      Arrows/PgUp/PgDn/Home/End: Scroll focused pane\n"
	"      Mouse wheel           : Scroll pane under pointer\n"
	"      Mouse click header    : Sort by column\n"
	"      s / S                 : Cycle sort field next / previous\n"
	"      R                     : Toggle realtime sorting\n"
	"      b / B                 : Switch band next / previous\n"
	"      v                     : Show channel availability for active band\n"
	"      w                     : Write buffered WPA/PMKID snapshot\n"
	"      t                     : Tune channel and stop hopping\n"
	"      l                     : Lock to selected AP channel\n"
	"      r                     : Resume channel hopping\n"
	"      d                     : Run station logging/deauth workflow\n"
	"      c                     : Clear AP filter\n"
	"      o                     : Toggle colors\n"
	"      M                     : Toggle mouse capture\n"
	"      q                     : Quit\n"
	"      Hopper warnings       : Driver refused a channel/frequency; try b/B for band\n"
	"\n"
	"      --help                : Displays this usage screen\n"
	"\n";

static void airodump_usage(void)
{
	char * const l_usage = getVersion(
		"Airodump-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf(usage, l_usage);
	free(l_usage);
}

static int is_filtered_netmask(const uint8_t * bssid)
{
	REQUIRE(bssid != NULL);

	unsigned char mac1[6];
	unsigned char mac2[6];
	int i;

	for (i = 0; i < 6; i++)
	{
		mac1[i] = bssid[i] & opt.f_netmask[i];
		mac2[i] = opt.f_bssid[i] & opt.f_netmask[i];
	}

	if (memcmp(mac1, mac2, 6) != 0)
	{
		return (1);
	}

	return (0);
}

int is_filtered_essid(const uint8_t * essid)
{
	REQUIRE(essid != NULL);

	int ret = 0;
	int i;

	if (lopt.f_essid)
	{
		for (i = 0; i < lopt.f_essid_count; i++)
		{
			if (strncmp((char *) essid, lopt.f_essid[i], ESSID_LENGTH) == 0)
			{
				return (0);
			}
		}

		ret = 1;
	}

#ifdef HAVE_PCRE
	if (lopt.f_essid_regex)
	{
		return pcre_exec(lopt.f_essid_regex,
						 NULL,
						 (char *) essid,
						 (int) strnlen((char *) essid, ESSID_LENGTH),
						 0,
						 0,
						 NULL,
						 0)
			   < 0;
	}
#endif

	return (ret);
}

static void update_rx_quality(void)
{
	unsigned long time_diff, capt_time, miss_time;
	int missed_frames;
	struct AP_info * ap_cur = NULL;
	struct ST_info * st_cur = NULL;
	struct timeval cur_time;

	ap_cur = lopt.ap_1st;
	st_cur = lopt.st_1st;

	gettimeofday(&cur_time, NULL);

	/* accesspoints */
	while (ap_cur != NULL)
	{
		time_diff = 1000000UL * (cur_time.tv_sec - ap_cur->ftimer.tv_sec)
					+ (cur_time.tv_usec - ap_cur->ftimer.tv_usec);

		/* update every `QLT_TIME`seconds if the rate is low, or every 500ms
		 * otherwise */
		if ((ap_cur->fcapt >= QLT_COUNT && time_diff > 500000)
			|| time_diff > (QLT_TIME * 1000000))
		{
			/* at least one frame captured */
			if (ap_cur->fcapt > 1)
			{
				capt_time
					= (1000000UL * (ap_cur->ftimel.tv_sec
									- ap_cur->ftimef.tv_sec) // time between
					   // first and last
					   // captured frame
					   + (ap_cur->ftimel.tv_usec - ap_cur->ftimef.tv_usec));

				miss_time
					= (1000000UL * (ap_cur->ftimef.tv_sec
									- ap_cur->ftimer.tv_sec) // time between
					   // timer reset and
					   // first frame
					   + (ap_cur->ftimef.tv_usec - ap_cur->ftimer.tv_usec))
					  + (1000000UL * (cur_time.tv_sec
									  - ap_cur->ftimel.tv_sec) // time between
						 // last frame and
						 // this moment
						 + (cur_time.tv_usec - ap_cur->ftimel.tv_usec));

				// number of frames missed at the time where no frames were
				// captured; extrapolated by assuming a constant framerate
				if (capt_time > 0 && miss_time > 200000)
				{
					missed_frames
						= (int) (((float) miss_time / (float) capt_time)
								 * ((float) ap_cur->fcapt
									+ (float) ap_cur->fmiss));
					ap_cur->fmiss += missed_frames;
				}

				ap_cur->rx_quality
					= (int) (((float) ap_cur->fcapt
							  / ((float) ap_cur->fcapt + (float) ap_cur->fmiss))
							 *
#if defined(__x86_64__) && defined(__CYGWIN__)
							 (0.0f + 100));
#else
							 100.0f);
#endif
			}
			else
				ap_cur->rx_quality = 0; /* no packets -> zero quality */

			/* normalize, in case the seq numbers are not iterating */
			if (ap_cur->rx_quality > 100) ap_cur->rx_quality = 100;
			if (ap_cur->rx_quality < 0) ap_cur->rx_quality = 0;

			/* reset variables */
			ap_cur->fcapt = 0;
			ap_cur->fmiss = 0;
			gettimeofday(&(ap_cur->ftimer), NULL);
		}
		ap_cur = ap_cur->next;
	}

	/* stations */
	while (st_cur != NULL)
	{
		time_diff = 1000000UL * (cur_time.tv_sec - st_cur->ftimer.tv_sec)
					+ (cur_time.tv_usec - st_cur->ftimer.tv_usec);

		if (time_diff > 10000000)
		{
			st_cur->missed = 0;
			gettimeofday(&(st_cur->ftimer), NULL);
		}

		st_cur = st_cur->next;
	}
}

static int update_dataps(void)
{
	struct timeval tv;
	struct AP_info * ap_cur;
	struct NA_info * na_cur;
	int ps;
	unsigned long diff;
	float pause;
	time_t sec;
	suseconds_t usec;

	gettimeofday(&tv, NULL);

	ap_cur = lopt.ap_end;

	while (ap_cur != NULL)
	{
		sec = (tv.tv_sec - ap_cur->tv.tv_sec);
		usec = (tv.tv_usec - ap_cur->tv.tv_usec);
#if defined(__x86_64__) && defined(__CYGWIN__)
		pause = (((sec * (0.0f + 1000000.0f) + usec)) / ((0.0f + 1000000.0f)));
#else
		pause = (sec * 1000000.0f + usec) / (1000000.0f);
#endif
		if (pause > 2.0f)
		{
			diff = ap_cur->nb_data - ap_cur->nb_data_old;
			ps = (int) (((float) diff) / pause);
			ap_cur->nb_dataps = ps;
			ap_cur->nb_data_old = ap_cur->nb_data;
			gettimeofday(&(ap_cur->tv), NULL);
		}
		ap_cur = ap_cur->prev;
	}

	na_cur = lopt.na_1st;

	while (na_cur != NULL)
	{
		sec = (tv.tv_sec - na_cur->tv.tv_sec);
		usec = (tv.tv_usec - na_cur->tv.tv_usec);
#if defined(__x86_64__) && defined(__CYGWIN__)
		pause = (((sec * (0.0f + 1000000.0f) + usec)) / ((0.0f + 1000000.0f)));
#else
		pause = (sec * 1000000.0f + usec) / (1000000.0f);
#endif
		if (pause > 2.0f)
		{
			diff = (unsigned long) (na_cur->ack - na_cur->ack_old);
			ps = (int) (((float) diff) / pause);
			na_cur->ackps = ps;
			na_cur->ack_old = na_cur->ack;
			gettimeofday(&(na_cur->tv), NULL);
		}
		na_cur = na_cur->next;
	}

	return (0);
}

static int list_tail_free(struct pkt_buf ** list)
{
	struct pkt_buf ** pkts;
	struct pkt_buf * next;

	if (list == NULL) return 1;

	pkts = list;

	while (*pkts != NULL)
	{
		next = (*pkts)->next;
		if ((*pkts)->packet)
		{
			free((*pkts)->packet);
			(*pkts)->packet = NULL;
		}

		free(*pkts);
		*pkts = NULL;
		*pkts = next;
	}

	*list = NULL;

	return (0);
}

static int
list_add_packet(struct pkt_buf ** list, int length, unsigned char * packet)
{
	struct pkt_buf * next;

	if (length <= 0) return 1;
	if (packet == NULL) return 1;
	if (list == NULL) return 1;

	next = *list;

	*list = (struct pkt_buf *) malloc(sizeof(struct pkt_buf));
	if (*list == NULL) return 1;
	(*list)->packet = (unsigned char *) malloc((size_t) length);
	if ((*list)->packet == NULL) return 1;

	memcpy((*list)->packet, packet, (size_t) length);
	(*list)->next = next;
	(*list)->length = (uint16_t) length;
	gettimeofday(&((*list)->ctime), NULL);

	return (0);
}

/*
 * Check if the same IV was used if the first two bytes were the same.
 * If they are not identical, it would complain.
 * The reason is that the first two bytes unencrypted are 'aa'
 * so with the same IV it should always be encrypted to the same thing.
 */
static int
list_check_decloak(struct pkt_buf ** list, int length, const uint8_t * packet)
{
	struct pkt_buf * next;
	struct timeval tv1;
	unsigned long timediff;
	int i, correct;

	if (packet == NULL) return (1);
	if (list == NULL) return (1);
	if (*list == NULL) return (1);
	if (length <= 0) return (1);
	next = *list;

	gettimeofday(&tv1, NULL);

	timediff = (((tv1.tv_sec - ((*list)->ctime.tv_sec)) * 1000000UL)
				+ (tv1.tv_usec - ((*list)->ctime.tv_usec)))
			   / 1000;
	if (timediff > BUFFER_TIME)
	{
		list_tail_free(list);
		next = NULL;
	}

	while (next != NULL)
	{
		if (next->next != NULL)
		{
			timediff = (((tv1.tv_sec - (next->next->ctime.tv_sec)) * 1000000UL)
						+ (tv1.tv_usec - (next->next->ctime.tv_usec)))
					   / 1000;
			if (timediff > BUFFER_TIME)
			{
				list_tail_free(&(next->next));
				break;
			}
		}
		if ((next->length + 4) == length)
		{
			correct = 1;
			// check for 4 bytes added after the end
			for (i = 28; i < length - 28; i++) // check everything (in the old
			// packet) after the IV
			// (including crc32 at the end)
			{
				if (next->packet[i] != packet[i])
				{
					correct = 0;
					break;
				}
			}
			if (!correct)
			{
				correct = 1;
				// check for 4 bytes added at the beginning
				for (i = 28; i < length - 28; i++) // check everything (in the
				// old packet) after the IV
				// (including crc32 at the
				// end)
				{
					if (next->packet[i] != packet[4 + i])
					{
						correct = 0;
						break;
					}
				}
			}
			if (correct == 1) return (0); // found decloaking!
		}
		next = next->next;
	}

	return (1); // didn't find decloak
}

static int remove_namac(unsigned char * mac)
{
	struct NA_info * na_cur = NULL;
	struct NA_info * na_prv = NULL;

	if (mac == NULL) return (-1);

	na_cur = lopt.na_1st;
	na_prv = NULL;

	while (na_cur != NULL)
	{
		if (!memcmp(na_cur->namac, mac, 6)) break;

		na_prv = na_cur;
		na_cur = na_cur->next;
	}

	/* if it's known, remove it */
	if (na_cur != NULL)
	{
		/* first in linked list */
		if (na_cur == lopt.na_1st)
		{
			lopt.na_1st = na_cur->next;
		}
		else
		{
			na_prv->next = na_cur->next;
		}
		free(na_cur);
	}

	return (0);
}

// NOTE(jbenden): This is also in ivstools.c
static int dump_add_packet(unsigned char * h80211,
						   int caplen,
						   struct rx_info * ri,
						   int cardnum)
{
	REQUIRE(h80211 != NULL);

	int seq, msd, offset, clen, o;
	size_t i;
	size_t n;
	size_t dlen;
	unsigned z;
	int type, length, numuni = 0;
	size_t numauth = 0;
	struct pcap_pkthdr pkh;
	struct timeval tv;
	struct ivs2_pkthdr ivs2;
	unsigned char *p, *org_p, c;
	unsigned char bssid[6];
	unsigned char stmac[6];
	unsigned char namac[6];
	unsigned char clear[2048];
	int weight[16];
	int num_xor = 0;

	size_t ppi_header_len = 0;
	uint8_t *packet_data = NULL;  // Ensure it's NULL initially
	size_t total_packet_size = 0; // Set to 0 to avoid uninitialized usage

	struct AP_info * ap_cur = NULL;
	struct ST_info * st_cur = NULL;
	struct NA_info * na_cur = NULL;
	struct AP_info * ap_prv = NULL;
	struct ST_info * st_prv = NULL;
	struct NA_info * na_prv = NULL;

	/* skip all non probe response frames in active scanning simulation mode */
	if (lopt.active_scan_sim > 0 && h80211[0] != 0x50) return (0);

	/* skip packets smaller than a 802.11 header */

	if (caplen < (int) sizeof(struct ieee80211_frame)) goto write_packet;

	/* skip (uninteresting) control frames */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
		goto write_packet;

	/* if it's a LLC null packet, just forget it (may change in the future) */

	if (((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA)
		&& (caplen > 28))
		if (memcmp(h80211 + 24, llcnull, 4) == 0) return (0);

	/* grab the sequence number */
	seq = ((h80211[22] >> 4) + (h80211[23] << 4));

	/* locate the access point's MAC address */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:
			memcpy(bssid, h80211 + 16, 6); //-V525
			break; // Adhoc
		case IEEE80211_FC1_DIR_TODS:
			memcpy(bssid, h80211 + 4, 6);
			break; // ToDS
		case IEEE80211_FC1_DIR_FROMDS:
		case IEEE80211_FC1_DIR_DSTODS:
			memcpy(bssid, h80211 + 10, 6);
			break; // WDS -> Transmitter taken as BSSID
		default:
			abort();
	}

	if (memcmp(opt.f_bssid, NULL_MAC, 6) != 0)
	{
		if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
		{
			if (is_filtered_netmask(bssid)) return (1);
		}
		else
		{
			if (memcmp(opt.f_bssid, bssid, 6) != 0) return (1);
		}
	}

	/* update our chained list of access points */

	ap_cur = lopt.ap_1st;
	ap_prv = NULL;

	while (ap_cur != NULL)
	{
		if (!memcmp(ap_cur->bssid, bssid, 6)) break;

		ap_prv = ap_cur;
		ap_cur = ap_cur->next;
	}

	/* if it's a new access point, add it */

	if (ap_cur == NULL)
	{
		if (!(ap_cur = (struct AP_info *) calloc(1, sizeof(struct AP_info))))
		{
			perror("calloc failed");
			return (1);
		}

		/* if mac is listed as unknown, remove it */
		remove_namac(bssid);

		if (lopt.ap_1st == NULL)
			lopt.ap_1st = ap_cur;
		else if (ap_prv != NULL)
			ap_prv->next = ap_cur;

		memcpy(ap_cur->bssid, bssid, 6);
		if (ap_cur->manuf == NULL)
		{
			ap_cur->manuf = get_manufacturer(
				ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2]);
		}

		ap_cur->nb_pkt = 0;
		ap_cur->prev = ap_prv;

		ap_cur->tinit = time(NULL);
		ap_cur->tlast = time(NULL);

		ap_cur->avg_power = -1;
		ap_cur->best_power = -1;
		ap_cur->power_index = -1;

		for (i = 0; i < NB_PWR; i++) ap_cur->power_lvl[i] = -1;

		ap_cur->channel = -1;
		ap_cur->band = 0;
		ap_cur->max_speed = -1;
		ap_cur->bss_load_station_count = -1;
		ap_cur->security = 0;

		ap_cur->ivbuf = NULL;
		ap_cur->ivbuf_size = 0;
		ap_cur->uiv_root = uniqueiv_init();

		ap_cur->nb_data = 0;
		ap_cur->nb_dataps = 0;
		ap_cur->nb_data_old = 0;
		gettimeofday(&(ap_cur->tv), NULL);

		ap_cur->dict_started = 0;

		ap_cur->key = NULL;

		lopt.ap_end = ap_cur;

		ap_cur->nb_bcn = 0;

		ap_cur->rx_quality = 0;
		ap_cur->fcapt = 0;
		ap_cur->fmiss = 0;
		ap_cur->last_seq = 0;
		gettimeofday(&(ap_cur->ftimef), NULL);
		gettimeofday(&(ap_cur->ftimel), NULL);
		gettimeofday(&(ap_cur->ftimer), NULL);

		ap_cur->ssid_length = 0;
		ap_cur->essid_stored = 0;
		memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
		ap_cur->timestamp = 0;

		ap_cur->decloak_detect = lopt.decloak;
		ap_cur->is_decloak = 0;
		ap_cur->packets = NULL;

		ap_cur->marked = 0;
		ap_cur->marked_color = 1;

		ap_cur->data_root = NULL;
		ap_cur->EAP_detected = 0;
		memcpy(ap_cur->gps_loc_min, lopt.gps_loc, sizeof(float) * 5); //-V512
		memcpy(ap_cur->gps_loc_max, lopt.gps_loc, sizeof(float) * 5); //-V512
		memcpy(ap_cur->gps_loc_best, lopt.gps_loc, sizeof(float) * 5); //-V512

		/* 802.11n and ac */
		ap_cur->channel_width = CHANNEL_22MHZ; // 20MHz by default
		memset(ap_cur->standard, 0, 3);

		ap_cur->n_channel.sec_channel = -1;
		ap_cur->n_channel.short_gi_20 = 0;
		ap_cur->n_channel.short_gi_40 = 0;
		ap_cur->n_channel.any_chan_width = 0;
		ap_cur->n_channel.mcs_index = -1;

		ap_cur->ac_channel.center_sgmt[0] = 0;
		ap_cur->ac_channel.center_sgmt[1] = 0;
		ap_cur->ac_channel.mu_mimo = 0;
		ap_cur->ac_channel.short_gi_80 = 0;
		ap_cur->ac_channel.short_gi_160 = 0;
		ap_cur->ac_channel.split_chan = 0;
		ap_cur->ac_channel.mhz_160_chan = 0;
		ap_cur->ac_channel.wave_2 = 0;
		memset(ap_cur->ac_channel.mcs_index, 0, MAX_AC_MCS_INDEX);

		/* 802.11ax */
		ap_cur->ax_channel.center_sgmt[0] = 0;
		ap_cur->ax_channel.center_sgmt[1] = 0;
		ap_cur->ax_channel.split_chan = 0;
		ap_cur->ax_channel.mhz_160_chan = 0;

	}

	/* update the last time seen */

	ap_cur->tlast = time(NULL);

	/* only update power if packets comes from
	 * the AP: either type == mgmt and SA == BSSID,
	 * or FromDS == 1 and ToDS == 0 */

	if (((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_NODS
		 && memcmp(h80211 + 10, bssid, 6) == 0)
		|| ((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_FROMDS))
	{
		ap_cur->power_index = (ap_cur->power_index + 1) % NB_PWR;
		ap_cur->power_lvl[ap_cur->power_index] = ri->ri_power;

		// Moving exponential average
		// ma_new = alpha * new_sample + (1-alpha) * ma_old;
		ap_cur->avg_power
			= (int) (0.99f * ri->ri_power + (1.f - 0.99f) * ap_cur->avg_power);

		if (ap_cur->avg_power > ap_cur->best_power)
		{
			ap_cur->best_power = ap_cur->avg_power;
			memcpy(ap_cur->gps_loc_best, //-V512
				   lopt.gps_loc,
				   sizeof(float) * 5);
		}

		/* every packet in here comes from the AP */

		if (lopt.gps_loc[0] > ap_cur->gps_loc_max[0])
			ap_cur->gps_loc_max[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] > ap_cur->gps_loc_max[1])
			ap_cur->gps_loc_max[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] > ap_cur->gps_loc_max[2])
			ap_cur->gps_loc_max[2] = lopt.gps_loc[2];

		if (lopt.gps_loc[0] < ap_cur->gps_loc_min[0])
			ap_cur->gps_loc_min[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] < ap_cur->gps_loc_min[1])
			ap_cur->gps_loc_min[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] < ap_cur->gps_loc_min[2])
			ap_cur->gps_loc_min[2] = lopt.gps_loc[2];
		//        printf("seqnum: %i\n", seq);

		if (ap_cur->fcapt == 0 && ap_cur->fmiss == 0)
			gettimeofday(&(ap_cur->ftimef), NULL);
		if (ap_cur->last_seq != 0)
			ap_cur->fmiss += (seq - ap_cur->last_seq - 1);
		ap_cur->last_seq = (uint16_t) seq;
		ap_cur->fcapt++;
		gettimeofday(&(ap_cur->ftimel), NULL);

		/* if we are writing to a file and want to make a continuous rolling log save the data here */
		if (opt.record_data && opt.output_format_log_csv)
		{
			/* Write out our rolling log every time we see data from an AP */

			dump_write_airodump_ng_logcsv_add_ap(
				ap_cur, ri->ri_power, &lopt.gps_time, lopt.gps_loc);
		}

		//         if(ap_cur->fcapt >= QLT_COUNT) update_rx_quality();
	}

	switch (h80211[0])
	{
		case IEEE80211_FC0_SUBTYPE_BEACON:
			ap_cur->nb_bcn++;
			break;

		case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
			/* reset the WPS state */
			ap_cur->wps.state = 0xFF;
			ap_cur->wps.ap_setup_locked = 0;
			break;

		default:
			break;
	}

	ap_cur->nb_pkt++;

	/* locate the station MAC in the 802.11 header */

	switch (h80211[1] & IEEE80211_FC1_DIR_MASK)
	{
		case IEEE80211_FC1_DIR_NODS:

			/* if management, check that SA != BSSID */

			if (memcmp(h80211 + 10, bssid, 6) == 0) goto skip_station;

			memcpy(stmac, h80211 + 10, 6);
			break;

		case IEEE80211_FC1_DIR_TODS:

			/* ToDS packet, must come from a client */

			memcpy(stmac, h80211 + 10, 6);
			break;

		case IEEE80211_FC1_DIR_FROMDS:

			/* FromDS packet, reject broadcast MACs */

			if ((h80211[4] % 2) != 0) goto skip_station;
			memcpy(stmac, h80211 + 4, 6);
			break;

		case IEEE80211_FC1_DIR_DSTODS:
			goto skip_station;

		default:
			abort();
	}

	/* update our chained list of wireless stations */

	st_cur = lopt.st_1st;
	st_prv = NULL;

	while (st_cur != NULL)
	{
		if (!memcmp(st_cur->stmac, stmac, 6)) break;

		st_prv = st_cur;
		st_cur = st_cur->next;
	}

	/* if it's a new client, add it */

	if (st_cur == NULL)
	{
		if (!(st_cur = (struct ST_info *) calloc(1, sizeof(struct ST_info))))
		{
			perror("calloc failed");
			return (1);
		}

		/* if mac is listed as unknown, remove it */
		remove_namac(stmac);

		memset(st_cur, 0, sizeof(struct ST_info));

		if (lopt.st_1st == NULL)
			lopt.st_1st = st_cur;
		else
			st_prv->next = st_cur;

		memcpy(st_cur->stmac, stmac, 6);

		if (st_cur->manuf == NULL)
		{
			st_cur->manuf = get_manufacturer(
				st_cur->stmac[0], st_cur->stmac[1], st_cur->stmac[2]);
		}

		st_cur->nb_pkt = 0;

		st_cur->prev = st_prv;

		st_cur->tinit = time(NULL);
		st_cur->tlast = time(NULL);

		st_cur->power = -1;
		st_cur->best_power = -1;
		st_cur->rate_to = -1;
		st_cur->rate_from = -1;

		st_cur->probe_index = -1;
		st_cur->missed = 0;
		st_cur->lastseq = 0;
	st_cur->qos_fr_ds = 0;
	st_cur->qos_to_ds = 0;
	st_cur->channel = 0;
	st_cur->band = 0;

		gettimeofday(&(st_cur->ftimer), NULL);

		memcpy(st_cur->gps_loc_min, //-V512
			   lopt.gps_loc,
			   sizeof(st_cur->gps_loc_min));
		memcpy(st_cur->gps_loc_max, //-V512
			   lopt.gps_loc,
			   sizeof(st_cur->gps_loc_max));
		memcpy( //-V512
			st_cur->gps_loc_best,
			lopt.gps_loc,
			sizeof(st_cur->gps_loc_best));

		for (i = 0; i < NB_PRB; i++)
		{
			memset(st_cur->probes[i], 0, sizeof(st_cur->probes[i]));
			st_cur->ssid_length[i] = 0;
		}

		lopt.st_end = st_cur;
	}

	if (st_cur->base == NULL || memcmp(ap_cur->bssid, BROADCAST, 6) != 0)
		st_cur->base = ap_cur;

	// update bitrate to station
	if ((h80211[1] & 3) == 2) st_cur->rate_to = ri->ri_rate;

	/* update the last time seen */

	st_cur->tlast = time(NULL);

	/* only update power if packets comes from the
	 * client: either type == Mgmt and SA != BSSID,
	 * or FromDS == 0 and ToDS == 1 */

	if (((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_NODS
		 && memcmp(h80211 + 10, bssid, 6) != 0)
		|| ((h80211[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_TODS))
	{
		st_cur->power = ri->ri_power;
		if (ri->ri_power > st_cur->best_power)
		{
			st_cur->best_power = ri->ri_power;
			memcpy(ap_cur->gps_loc_best, //-V512
				   lopt.gps_loc,
				   sizeof(st_cur->gps_loc_best));
		}

		st_cur->rate_from = ri->ri_rate;
		if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
			st_cur->channel = ri->ri_channel;
		else
			st_cur->channel = lopt.channel[cardnum];
		st_cur->band = band_from_rx_info(ri, st_cur->channel);

		if (lopt.gps_loc[0] > st_cur->gps_loc_max[0])
			st_cur->gps_loc_max[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] > st_cur->gps_loc_max[1])
			st_cur->gps_loc_max[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] > st_cur->gps_loc_max[2])
			st_cur->gps_loc_max[2] = lopt.gps_loc[2];

		if (lopt.gps_loc[0] < st_cur->gps_loc_min[0])
			st_cur->gps_loc_min[0] = lopt.gps_loc[0];
		if (lopt.gps_loc[1] < st_cur->gps_loc_min[1])
			st_cur->gps_loc_min[1] = lopt.gps_loc[1];
		if (lopt.gps_loc[2] < st_cur->gps_loc_min[2])
			st_cur->gps_loc_min[2] = lopt.gps_loc[2];

		if (st_cur->lastseq != 0)
		{
			msd = seq - st_cur->lastseq - 1;
			if (msd > 0 && msd < 1000) st_cur->missed += msd;
		}
		st_cur->lastseq = (uint16_t) seq;

		/* if we are writing to a file and want to make a continuous rolling log save the data here */
		if (opt.record_data && opt.output_format_log_csv)
		{
			/* Write out our rolling log every time we see data from a client */
			dump_write_airodump_ng_logcsv_add_client(
				ap_cur, st_cur, ri->ri_power, &lopt.gps_time, lopt.gps_loc);
		}
	}

	st_cur->nb_pkt++;

skip_station:

	/* packet parsing: Probe Request */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_REQ && st_cur != NULL)
	{
		p = h80211 + 24;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				n = MIN(ESSID_LENGTH, p[1]);

				for (i = 0; i < n; i++)
					if (p[2 + i] > 0 && p[2 + i] < ' ') goto skip_probe;

				log_distinct_probe_essid(st_cur,
										 (const unsigned char *) (p + 2),
										 (size_t) n);

				/* got a valid ASCII probed ESSID, check if it's
				   already in the ring buffer */

				for (i = 0; i < NB_PRB; i++)
					if (memcmp(st_cur->probes[i], p + 2, n) == 0)
						goto skip_probe;

				st_cur->probe_index = (st_cur->probe_index + 1) % NB_PRB;
				memset(st_cur->probes[st_cur->probe_index], 0, 256);
				memcpy(
					st_cur->probes[st_cur->probe_index], p + 2, n); // twice?!
				st_cur->ssid_length[st_cur->probe_index] = (int) n;

				if (verifyssid((const unsigned char *)
								   st_cur->probes[st_cur->probe_index])
					== 0)
					for (i = 0; i < n; i++)
					{
						c = p[2 + i];
						if (c < 32) c = '.';
						st_cur->probes[st_cur->probe_index][i] = c;
					}

			}

			p += 2 + p[1];
		}
	}

skip_probe:

	/* packet parsing: Beacon or Probe Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		|| h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
	{
		if (!(ap_cur->security & (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)))
		{
			if ((h80211[34] & 0x10) >> 4)
				ap_cur->security |= STD_WEP | ENC_WEP;
			else
				ap_cur->security |= STD_OPN;
		}

		ap_cur->preamble = (h80211[34] & 0x20) >> 5;

		unsigned long long * tstamp = (unsigned long long *) (h80211 + 24);
		ap_cur->timestamp = letoh64(*tstamp);

		p = h80211 + 36;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			// only update the essid length if the new length is > the old one
			if (p[0] == 0x00 && (ap_cur->ssid_length < p[1]))
				ap_cur->ssid_length = p[1];

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				/* found a non-cloaked ESSID */
				n = MIN(ESSID_LENGTH, p[1]);

				memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
				memcpy(ap_cur->essid, p + 2, n);

				if (opt.f_ivs != NULL && !ap_cur->essid_stored)
				{
					memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
					ivs2.flags |= IVS2_ESSID;
					ivs2.len += ap_cur->ssid_length;

					if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
					{
						ivs2.flags |= IVS2_BSSID;
						ivs2.len += 6;
						memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
					}

					/* write header */
					if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
						!= (size_t) sizeof(struct ivs2_pkthdr))
					{
						perror("fwrite(IV header) failed");
						return (1);
					}

					/* write BSSID */
					if (ivs2.flags & IVS2_BSSID)
					{
						if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
							!= (size_t) 6)
						{
							perror("fwrite(IV bssid) failed");
							return (1);
						}
					}

					/* write essid */
					if (fwrite(ap_cur->essid,
							   1,
							   (size_t) ap_cur->ssid_length,
							   opt.f_ivs)
						!= (size_t) ap_cur->ssid_length)
					{
						perror("fwrite(IV essid) failed");
						return (1);
					}

					ap_cur->essid_stored = 1;
				}

				if (verifyssid(ap_cur->essid) == 0)
					for (i = 0; i < n; i++)
						if (ap_cur->essid[i] < 32) ap_cur->essid[i] = '.';
			}

			/* get the maximum speed in Mb and the AP's channel */

			if (p[0] == 0x01 || p[0] == 0x32)
			{
				if (ap_cur->max_speed < (p[1 + p[1]] & 0x7F) / 2)
					ap_cur->max_speed = (p[1 + p[1]] & 0x7F) / 2;
			}

			if (p[0] == 0x03)
			{
				ap_cur->channel = p[2];
				ap_cur->band = band_from_rx_info(ri, ap_cur->channel);
			}
			else if (p[0] == 0x3d)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				/* also get the channel from ht information->primary channel */
				ap_cur->channel = p[2];
				ap_cur->band = band_from_rx_info(ri, ap_cur->channel);

				// Get channel width and secondary channel
				switch (p[3] % 4)
				{
					case 0:
						// 20MHz
						ap_cur->channel_width = CHANNEL_20MHZ;
						break;
					case 1:
						// Above
						ap_cur->n_channel.sec_channel = 1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
					case 2:
						// Reserved
						break;
					case 3:
						// Below
						ap_cur->n_channel.sec_channel = -1;
						switch (ap_cur->channel_width)
						{
							case CHANNEL_UNKNOWN_WIDTH:
							case CHANNEL_3MHZ:
							case CHANNEL_5MHZ:
							case CHANNEL_10MHZ:
							case CHANNEL_20MHZ:
							case CHANNEL_22MHZ:
							case CHANNEL_30MHZ:
							case CHANNEL_20_OR_40MHZ:
								ap_cur->channel_width = CHANNEL_40MHZ;
								break;
							default:
								break;
						}
						break;
					default:
						break;
				}

				ap_cur->n_channel.any_chan_width = (uint8_t)((p[3] / 4) % 2);
			}

			// HT capabilities
			if (p[0] == 0x2d && p[1] > 18)
			{
				if (ap_cur->standard[0] == '\0')
				{
					ap_cur->standard[0] = 'n';
				}

				// Short GI for 20/40MHz
				ap_cur->n_channel.short_gi_20 = (uint8_t)((p[3] / 32) % 2);
				ap_cur->n_channel.short_gi_40 = (uint8_t)((p[3] / 64) % 2);

				// Parse MCS rate
				/*
				 * XXX: Sometimes TX and RX spatial stream # differ and none of
				 * the beacon
				 * have that. If someone happens to have such AP, open an issue
				 * with it.
				 * Ref:
				 * https://www.wireshark.org/lists/wireshark-bugs/201307/msg00098.html
				 * See IEEE standard 802.11-2012 table 8.126
				 *
				 * For now, just figure out the highest MCS rate.
				 */
				if ((unsigned char) ap_cur->n_channel.mcs_index == 0xff)
				{
					uint32_t rx_mcs_bitmask = 0;
					memcpy(&rx_mcs_bitmask, p + 5, sizeof(uint32_t));
					while (rx_mcs_bitmask)
					{
						++(ap_cur->n_channel.mcs_index);
						rx_mcs_bitmask /= 2;
					}
				}
			}

			// VHT Capabilities
			if (p[0] == 0xbf && p[1] >= 12)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				ap_cur->ac_channel.split_chan = (uint8_t)((p[3] / 4) % 4);

				ap_cur->ac_channel.short_gi_80 = (uint8_t)((p[3] / 32) % 2);
				ap_cur->ac_channel.short_gi_160 = (uint8_t)((p[3] / 64) % 2);

				ap_cur->ac_channel.mu_mimo = (uint8_t)((p[4] & 0x18) % 2);

				// A few things indicate Wave 2: MU-MIMO, 80+80 Channels
				ap_cur->ac_channel.wave_2
					= (uint8_t)((ap_cur->ac_channel.mu_mimo
								 || ap_cur->ac_channel.split_chan)
								% 2);

				// Maximum rates (16 bit)
				uint16_t tx_mcs = 0;
				memcpy(&tx_mcs, p + 10, sizeof(uint16_t));

				// Maximum of 8 SS, each uses 2 bits
				for (uint8_t stream_idx = 0; stream_idx < MAX_AC_MCS_INDEX;
					 ++stream_idx)
				{
					uint8_t mcs = (uint8_t)(tx_mcs % 4);

					// Unsupported -> No more spatial stream
					if (mcs == 3)
					{
						break;
					}
					switch (mcs)
					{
						case 0:
							// support of MCS 0-7
							ap_cur->ac_channel.mcs_index[stream_idx] = 7;
							break;
						case 1:
							// support of MCS 0-8
							ap_cur->ac_channel.mcs_index[stream_idx] = 8;
							break;
						case 2:
							// support of MCS 0-9
							ap_cur->ac_channel.mcs_index[stream_idx] = 9;
							break;
						default:
							break;
					}

					// Next spatial stream
					tx_mcs /= 4;
				}
			}

			// VHT Operations
			if (p[0] == 0xc0 && p[1] >= 3)
			{
				// Standard is AC
				strcpy(ap_cur->standard, "ac");

				// Channel width
				switch (p[2])
				{
					case 0:
						// 20 or 40MHz
						ap_cur->channel_width = CHANNEL_20_OR_40MHZ;
						break;
					case 1:
						ap_cur->channel_width = CHANNEL_80MHZ;
						break;
					case 2:
						ap_cur->channel_width = CHANNEL_160MHZ;
						break;
					case 3:
						// 80+80MHz
						ap_cur->channel_width = CHANNEL_80_80MHZ;
						ap_cur->ac_channel.split_chan = 1;
						break;
					default:
						break;
				}

				// 802.11ac channel center segments
				ap_cur->ac_channel.center_sgmt[0] = p[3];
				ap_cur->ac_channel.center_sgmt[1] = p[4];
			}

			// Ext tag
			if (p[0] == 0xff)
			{
				/*IEEE Std 802.11ax-2021
				  Figure 9-788k—6 GHz Operation Information field format
				  | Primary Channel | Control | Ch. Center Freq. Seg. 0 | Ch. Center Freq. Seg. 1 | Min. Rate |
			Octets 			1			 1					1						1					1
			
				  Figure 9-788l—Control field format
				  	B0		B1			B2			B3	B5		B6	B7
				  | Ch. Width | Duplicate Beacon | Reg. Info | Reserv. |	
			Bits		2				1				3		  2
				*/
				// HE Operation
				if (p[2] == 0x24 && p[1] >= 3) 
				{
					// Standard is AX
					strcpy(ap_cur->standard, "ax");
					
					// Process 3-byte HE Operations flags field with reverse byte order considering endian-ness
        			//uint32_t he_ops_flags = letoh32((*(uint32_t *) (p + 3)) & 0x00FFFFFF);
					uint32_t he_ops_flags = letoh24(p + 3);
					if (he_ops_flags & 0x20000) // Second to last bit in 24-bit field
					{
						// Parse 6GHz operation information (5 bytes)
						if (p[1] >= 10) // Ensure enough length for 6GHz operation info
						{
							// Primary channel number
							ap_cur->channel = p[9];
							ap_cur->band = 6;
							// Control flags
							uint8_t control_field = p[10];

							if (p[1] >= 12)
							{
								// Channel center frequency segments
								ap_cur->ax_channel.center_sgmt[0] = p[11];
								ap_cur->ax_channel.center_sgmt[1] = p[12];

								uint8_t ch_width = (control_field >> 6) & 0x03;

								switch (ch_width) {
									case 0:
										// 20 MHz
										ap_cur->channel_width = CHANNEL_20MHZ;
										break;
									case 1:
										// 40 MHz
										ap_cur->channel_width = CHANNEL_40MHZ;
										break;
									case 2:
										// 80 MHz
										ap_cur->channel_width = CHANNEL_80MHZ;
										break;
									case 3:
										// 80+80 MHz or 160 MHz
										// IEEE Std 802.11ax-2021 - pp.199
										if ((ap_cur->ax_channel.center_sgmt[1] != 0) && (ap_cur->ax_channel.center_sgmt[1] != ap_cur->ax_channel.center_sgmt[0]))
										{
											// 80+80 MHz scenario
											ap_cur->channel_width = CHANNEL_80_80MHZ;
											ap_cur->ax_channel.mhz_160_chan = 0;
											ap_cur->ax_channel.split_chan = 1;
										} else if (ap_cur->ax_channel.center_sgmt[0] != 0) {
											// 160 MHz scenario
											ap_cur->channel_width = CHANNEL_160MHZ;
											ap_cur->ax_channel.mhz_160_chan = 1;
											ap_cur->ax_channel.split_chan = 0;
										}
										break;
								}
							}
						}
					}
				}
			} 
			
			// Next
			if (p[0] == 0x0b && p[1] >= 5)
			{
				/* BSS Load: station count, channel utilization, available capacity */
				ap_cur->bss_load_station_count = (int) load16_le(p + 2);
			}

			// Next
			p += 2 + p[1];
			
		}

		// Now get max rate
		if (ap_cur->standard[0] == 'n' || strcmp(ap_cur->standard, "ac") == 0)
		{
			int sgi = 0;
			int width = 0;

			switch (ap_cur->channel_width)
			{
				case CHANNEL_20MHZ:
					width = 20;
					sgi = ap_cur->n_channel.short_gi_20;
					break;
				case CHANNEL_20_OR_40MHZ:
				case CHANNEL_40MHZ:
					width = 40;
					sgi = ap_cur->n_channel.short_gi_40;
					break;
				case CHANNEL_80MHZ:
					width = 80;
					sgi = ap_cur->ac_channel.short_gi_80;
					break;
				case CHANNEL_80_80MHZ:
				case CHANNEL_160MHZ:
					width = 160;
					sgi = ap_cur->ac_channel.short_gi_160;
					break;
				default:
					break;
			}

			if (width != 0)
			{
				// In case of ac, get the amount of spatial streams
				int amount_ss = 1;
				if (ap_cur->standard[0] != 'n')
				{
					for (amount_ss = 0;
						 amount_ss < MAX_AC_MCS_INDEX
						 && ap_cur->ac_channel.mcs_index[amount_ss] != 0;
						 ++amount_ss)
						;
				}

				// Get rate
				float max_rate
					= (ap_cur->standard[0] == 'n')
						  ? get_80211n_rate(
								width, sgi, ap_cur->n_channel.mcs_index)
						  : get_80211ac_rate(
								width,
								sgi,
								ap_cur->ac_channel.mcs_index[amount_ss - 1],
								amount_ss);

				// If no error, update rate
				if (max_rate > 0)
				{
					ap_cur->max_speed = (int) max_rate;
				}
			}
		}
	}

	/* packet parsing: Beacon & Probe response */
	/* TODO: Merge this if and the one above */
	if ((h80211[0] == IEEE80211_FC0_SUBTYPE_BEACON
		 || h80211[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
		&& caplen > 38)
	{
		p = h80211 + 36; // ignore hdr + fixed params

		while (p < h80211 + caplen)
		{
			type = p[0];
			length = p[1];
			if (p + 2 + length > h80211 + caplen)
			{
				/*                printf("error parsing tags! %p vs. %p (tag:
				%i, length: %i,position: %i)\n", (p+2+length), (h80211+caplen),
				type, length, (p-h80211));
				exit(1);*/
				break;
			}

			// Find WPA and RSN tags
			if ((type == 0xDD && (length >= 8)
				 && (memcmp(p + 2, "\x00\x50\xF2\x01\x01\x00", 6) == 0))
				|| (type == 0x30))
			{
				ap_cur->security &= ~(STD_WEP | ENC_WEP | STD_WPA);

				org_p = p;
				offset = 0;

				if (type == 0xDD)
				{
					// WPA defined in vendor specific tag -> WPA1 support
					ap_cur->security |= STD_WPA;
					offset = 4;
				}

				// RSN => WPA2
				if (type == 0x30)
				{
					ap_cur->security |= STD_WPA2;
					offset = 0;
				}

				if (length < (18 + offset))
				{
					p += length + 2;
					continue;
				}

				// Number of pairwise cipher suites
				if (p + 9 + offset > h80211 + caplen) break;
				numuni = p[8 + offset] + (p[9 + offset] << 8);

				// Number of Authentication Key Managament suites
				if (p + (11 + offset) + 4 * numuni > h80211 + caplen) break;
				numauth = p[(10 + offset) + 4 * numuni]
						  + (p[(11 + offset) + 4 * numuni] << 8);

				p += (10 + offset);

				if (type != 0x30)
				{
					if (p + (4 * numuni) + (2 + 4 * numauth) > h80211 + caplen)
						break;
				}
				else
				{
				if (p + (4 * numuni) + (2 + 4 * numauth) + 2
					> h80211 + caplen)
					break;
				}

				// Get the list of cipher suites
				for (i = 0; i < (size_t) numuni; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= ENC_WEP;
							break;
						case 0x02:
							ap_cur->security |= ENC_TKIP;
							break;
						case 0x03:
							ap_cur->security |= ENC_WRAP;
							break;
						case 0x0A:
						case 0x04:
							ap_cur->security |= ENC_CCMP;
							ap_cur->security |= STD_WPA2;
							break;
						case 0x05:
							ap_cur->security |= ENC_WEP104;
							break;
						case 0x08:
						case 0x09:
							ap_cur->security |= ENC_GCMP;
							ap_cur->security |= STD_WPA2;
							break;
						case 0x0B:
						case 0x0C:
							ap_cur->security |= ENC_GMAC;
							ap_cur->security |= STD_WPA2;
							break;
						default:
							break;
					}
				}

				p += 2 + 4 * numuni;

				// Get the AKM suites
				for (i = 0; i < numauth; i++)
				{
					switch (p[i * 4 + 3])
					{
						case 0x01:
							ap_cur->security |= AUTH_MGT;
							break;
						case 0x02:
							ap_cur->security |= AUTH_PSK;
							break;
						case 0x06:
						case 0x0d:
							ap_cur->security |= AUTH_CMAC;
							break;
						case 0x08:
							ap_cur->security |= AUTH_SAE;
							break;
						case 0x12:
							ap_cur->security |= AUTH_OWE;
							break;
						default:
							break;
					}
				}

				if (type == 0x30)
				{
					const unsigned char * rsn_cap = p + 2 + 4 * numauth;

					if (rsn_cap + 2 <= h80211 + caplen)
					{
						unsigned short rsn_caps
							= (unsigned short) (rsn_cap[0]
												| ((unsigned short) rsn_cap[1] << 8));

						if (rsn_caps & 0x0080)
							ap_cur->mfp_capable = 1;
						if (rsn_caps & 0x0040)
						{
							ap_cur->mfp_capable = 1;
							ap_cur->mfp_required = 1;
						}
					}
				}

				p = org_p + length + 2;
			}
			else if ((type == 0xDD && (length >= 8)
					  && (memcmp(p + 2, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
			{
				// QoS IE
				ap_cur->security |= STD_QOS;
				p += length + 2;
			}
			else if ((type == 0xDD && (length >= 4)
					  && (memcmp(p + 2, "\x00\x50\xF2\x04", 4) == 0)))
			{
				// WPS IE
				org_p = p;
				p += 6;
				int len = length, subtype = 0, sublen = 0;
				while (len >= 4)
				{
					subtype = (p[0] << 8) + p[1];
					sublen = (p[2] << 8) + p[3];
					if (sublen > len) break;
					switch (subtype)
					{
						case 0x104a: // WPS Version
							ap_cur->wps.version = p[4];
							break;
						case 0x1011: // Device Name
						case 0x1012: // Device Password ID
						case 0x1021: // Manufacturer
						case 0x1023: // Model
						case 0x1024: // Model Number
						case 0x103b: // Response Type
						case 0x103c: // RF Bands
						case 0x1041: // Selected Registrar
						case 0x1042: // Serial Number
							break;
						case 0x1044: // WPS State
							ap_cur->wps.state = p[4];
							break;
						case 0x1047: // UUID Enrollee
						case 0x1049: // Vendor Extension
							if (memcmp(&p[4], "\x00\x37\x2A", 3) == 0)
							{
								unsigned char * pwfa = &p[7];
								int wfa_len = ntohs(*((short *) &p[2]));
								while (wfa_len > 0)
								{
									if (*pwfa == 0)
									{ // Version2
										ap_cur->wps.version = pwfa[2];
										break;
									}
									wfa_len -= pwfa[1] + 2;
									pwfa += pwfa[1] + 2;
								}
							}
							break;
						case 0x1054: // Primary Device Type
							break;
						case 0x1057: // AP Setup Locked
							ap_cur->wps.ap_setup_locked = p[4];
							break;
						case 0x1008: // Config Methods
						case 0x1053: // Selected Registrar Config Methods
							ap_cur->wps.meth = (p[4] << 8) + p[5];
							break;
						default: // Unknown type-length-value
							break;
					}
					p += sublen + 4;
					len -= sublen + 4;
				}
				p = org_p + length + 2;
			}
			else
				p += length + 2;
		}
	}

	/* packet parsing: Authentication Response */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_AUTH && caplen >= 30)
	{
		if (ap_cur->security & STD_WEP)
		{
			// successful step 2 or 4 (coming from the AP)
			if (memcmp(h80211 + 28, "\x00\x00", 2) == 0
				&& (h80211[26] == 0x02 || h80211[26] == 0x04))
			{
				ap_cur->security &= ~(AUTH_OPN | AUTH_PSK | AUTH_MGT);
				if (h80211[24] == 0x00) ap_cur->security |= AUTH_OPN;
				if (h80211[24] == 0x01) ap_cur->security |= AUTH_PSK;
			}
		}
	}

	/* packet parsing: Association Request */

	if (h80211[0] == IEEE80211_FC0_SUBTYPE_ASSOC_REQ && caplen > 28)
	{
		p = h80211 + 28;

		while (p < h80211 + caplen)
		{
			if (p + 2 + p[1] > h80211 + caplen) break;

			if (p[0] == 0x00 && p[1] > 0 && p[2] != '\0'
				&& (p[1] > 1 || p[2] != ' '))
			{
				/* found a non-cloaked ESSID */
				n = MIN(ESSID_LENGTH, p[1]);

				memset(ap_cur->essid, 0, ESSID_LENGTH + 1);
				memcpy(ap_cur->essid, p + 2, n);
				ap_cur->ssid_length = (int) n;

				if (opt.f_ivs != NULL && !ap_cur->essid_stored)
				{
					memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
					ivs2.flags |= IVS2_ESSID;
					ivs2.len += ap_cur->ssid_length;

					if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
					{
						ivs2.flags |= IVS2_BSSID;
						ivs2.len += 6;
						memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
					}

					/* write header */
					if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
						!= (size_t) sizeof(struct ivs2_pkthdr))
					{
						perror("fwrite(IV header) failed");
						return (1);
					}

					/* write BSSID */
					if (ivs2.flags & IVS2_BSSID)
					{
						if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
							!= (size_t) 6)
						{
							perror("fwrite(IV bssid) failed");
							return (1);
						}
					}

					/* write essid */
					if (fwrite(ap_cur->essid,
							   1,
							   (size_t) ap_cur->ssid_length,
							   opt.f_ivs)
						!= (size_t) ap_cur->ssid_length)
					{
						perror("fwrite(IV essid) failed");
						return (1);
					}

					ap_cur->essid_stored = 1;
				}

				if (verifyssid(ap_cur->essid) == 0)
					for (i = 0; i < n; i++)
						if (ap_cur->essid[i] < 32) ap_cur->essid[i] = '.';
			}

			p += 2 + p[1];
		}
		if (st_cur != NULL) st_cur->wpa.state = 0;
	}

	/* packet parsing: some data */

	if ((h80211[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA)
	{
		/* update the channel if we didn't get any beacon */

		if (ap_cur->channel == -1)
		{
			if (ri->ri_channel > 0 && ri->ri_channel <= HIGHEST_CHANNEL)
				ap_cur->channel = ri->ri_channel;
			else
				ap_cur->channel = lopt.channel[cardnum];
		}
		ap_cur->band = band_from_rx_info(ri, ap_cur->channel);

		/* check the SNAP header to see if data is encrypted */

		z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
				? 24
				: 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80)
		{
			z += 2;
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 1;
				else
					st_cur->qos_fr_ds = 1;
			}
		}
		else
		{
			if (st_cur != NULL)
			{
				if ((h80211[1] & 3) == 1) // ToDS
					st_cur->qos_to_ds = 0;
				else
					st_cur->qos_fr_ds = 0;
			}
		}

		if (z == 24)
		{
			if (ap_cur->decloak_detect && (ap_cur->security & STD_WEP) != 0)
			{
				if (list_check_decloak(&(ap_cur->packets), caplen, h80211) != 0)
				{
					list_add_packet(&(ap_cur->packets), caplen, h80211);
				}
				else
				{
					ap_cur->is_decloak = 1;
					ap_cur->decloak_detect = 0;
					list_tail_free(&(ap_cur->packets));
					memset(lopt.message, '\x00', sizeof(lopt.message));
					snprintf(lopt.message,
							 sizeof(lopt.message) - 1,
							 "][ Decloak: %02X:%02X:%02X:%02X:%02X:%02X ",
							 ap_cur->bssid[0],
							 ap_cur->bssid[1],
							 ap_cur->bssid[2],
							 ap_cur->bssid[3],
							 ap_cur->bssid[4],
							 ap_cur->bssid[5]);
					append_tui_message_history_now(lopt.message);
				}
			}
		}

		if (z + 26 > (unsigned) caplen) goto write_packet;

		if (h80211[z] == h80211[z + 1] && h80211[z + 2] == 0x03)
		{
			//            if( ap_cur->encryption < 0 )
			//                ap_cur->encryption = 0;

			/* if ethertype == IPv4, find the LAN address */

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x00
				&& (h80211[1] & 3) == 0x01)
				memcpy(ap_cur->lanip, &h80211[z + 20], 4);

			if (h80211[z + 6] == 0x08 && h80211[z + 7] == 0x06)
				memcpy(ap_cur->lanip, &h80211[z + 22], 4);
		}
		//        else
		//            ap_cur->encryption = 2 + ( ( h80211[z + 3] & 0x20 ) >> 5
		//            );

		if (ap_cur->security == 0 || (ap_cur->security & STD_WEP))
		{
			if ((h80211[1] & 0x40) != 0x40)
			{
				ap_cur->security |= STD_OPN;
			}
			else
			{
				if ((h80211[z + 3] & 0x20) == 0x20)
				{
					ap_cur->security |= STD_WPA;
				}
				else
				{
					ap_cur->security |= STD_WEP;
					if ((h80211[z + 3] & 0xC0) != 0x00)
					{
						ap_cur->security |= ENC_WEP40;
					}
					else
					{
						ap_cur->security &= ~ENC_WEP40;
						ap_cur->security |= ENC_WEP;
					}
				}
			}
		}

		if (z + 10 > (unsigned) caplen) goto write_packet;

		if (ap_cur->security & STD_WEP)
		{
			/* WEP: check if we've already seen this IV */

			if (!uniqueiv_check(ap_cur->uiv_root, &h80211[z]))
			{
				/* first time seen IVs */

				if (opt.f_ivs != NULL)
				{
					memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
					ivs2.flags = 0;
					ivs2.len = 0;

					/* datalen = caplen - (header+iv+ivs) */
					dlen = caplen - z - 4 - 4; // original data len
					if (dlen > 2048) dlen = 2048;
					// get cleartext + len + 4(iv+idx)
					num_xor = known_clear(clear, &clen, weight, h80211, dlen);
					if (num_xor == 1)
					{
						ivs2.flags |= IVS2_XOR;
						ivs2.len += clen + 4;
						/* reveal keystream (plain^encrypted) */
						for (n = 0; n < (size_t)(ivs2.len - 4); n++)
						{
							clear[n] = (uint8_t)((clear[n] ^ h80211[z + 4 + n])
												 & 0xFF);
						}
						// clear is now the keystream
					}
					else
					{
						// do it again to get it 2 bytes higher
						num_xor = known_clear(
							clear + 2, &clen, weight, h80211, dlen);
						ivs2.flags |= IVS2_PTW;
						// len = 4(iv+idx) + 1(num of keystreams) + 1(len per
						// keystream) + 32*num_xor + 16*sizeof(int)(weight[16])
						ivs2.len += 4 + 1 + 1 + 32 * num_xor + 16 * sizeof(int);
						clear[0] = (uint8_t) num_xor;
						clear[1] = (uint8_t) clen;
						/* reveal keystream (plain^encrypted) */
						for (o = 0; o < num_xor; o++)
						{
							for (n = 0; n < (size_t)(ivs2.len - 4); n++)
							{
								clear[2 + n + o * 32] = (uint8_t)(
									(clear[2 + n + o * 32] ^ h80211[z + 4 + n])
									& 0xFF);
							}
						}
						memcpy(clear + 4 + 1 + 1 + 32 * num_xor,
							   weight,
							   16 * sizeof(int));
						// clear is now the keystream
					}

					if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
					{
						ivs2.flags |= IVS2_BSSID;
						ivs2.len += 6;
						memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
					}

					if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
						!= (size_t) sizeof(struct ivs2_pkthdr))
					{
						perror("fwrite(IV header) failed");
						return (EXIT_FAILURE);
					}

					if (ivs2.flags & IVS2_BSSID)
					{
						if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
							!= (size_t) 6)
						{
							perror("fwrite(IV bssid) failed");
							return (1);
						}
						ivs2.len -= 6;
					}

					if (fwrite(h80211 + z, 1, 4, opt.f_ivs) != (size_t) 4)
					{
						perror("fwrite(IV iv+idx) failed");
						return (EXIT_FAILURE);
					}
					ivs2.len -= 4;

					if (fwrite(clear, 1, ivs2.len, opt.f_ivs)
						!= (size_t) ivs2.len)
					{
						perror("fwrite(IV keystream) failed");
						return (EXIT_FAILURE);
					}
				}

				uniqueiv_mark(ap_cur->uiv_root, &h80211[z]);

				ap_cur->nb_data++;
			}

			// Record all data linked to IV to detect WEP Cloaking
			if (opt.f_ivs == NULL && lopt.detect_anomaly)
			{
				// Only allocate this when seeing WEP AP
				if (ap_cur->data_root == NULL) ap_cur->data_root = data_init();

				// Only works with full capture, not IV-only captures
				if (data_check(ap_cur->data_root, &h80211[z], &h80211[z + 4])
						== CLOAKING
					&& ap_cur->EAP_detected == 0)
				{

					// If no EAP/EAP was detected, indicate WEP cloaking
					memset(lopt.message, '\x00', sizeof(lopt.message));
					snprintf(lopt.message,
							 sizeof(lopt.message) - 1,
							 "][ WEP Cloaking: %02X:%02X:%02X:%02X:%02X:%02X ",
							 ap_cur->bssid[0],
							 ap_cur->bssid[1],
							 ap_cur->bssid[2],
							 ap_cur->bssid[3],
							 ap_cur->bssid[4],
							 ap_cur->bssid[5]);
					append_tui_message_history_now(lopt.message);
				}
			}
		}
		else
		{
			ap_cur->nb_data++;
		}

		z = ((h80211[1] & IEEE80211_FC1_DIR_MASK) != IEEE80211_FC1_DIR_DSTODS)
				? 24
				: 30;

		/* Check if 802.11e (QoS) */
		if ((h80211[0] & 0x80) == 0x80) z += 2;

		if (z + 26 > (unsigned) caplen) goto write_packet;

		z += 6; // skip LLC header

		/* check ethertype == EAPOL */
		if (h80211[z] == 0x88 && h80211[z + 1] == 0x8E
			&& (h80211[1] & 0x40) != 0x40)
		{
			ap_cur->EAP_detected = 1;

			z += 2; // skip ethertype

			if (st_cur == NULL) goto write_packet;

			/* frame 1: Pairwise == 1, Install == 0, Ack == 1, MIC == 0 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) == 0)
			{
				memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);

				st_cur->wpa.state = 1;

				if (h80211[z + 99] == IEEE80211_ELEMID_VENDOR)
				{
					const uint8_t rsn_oui[] = {RSN_OUI & 0xff,
											   (RSN_OUI >> 8) & 0xff,
											   (RSN_OUI >> 16) & 0xff};

					if (memcmp(rsn_oui, &h80211[z + 101], 3) == 0
						&& h80211[z + 104] == RSN_CSE_CCMP)
					{
						if (memcmp(ZERO, &h80211[z + 105], 16) != 0) //-V512
						{
							// Got a PMKID value?!
							memcpy(st_cur->wpa.pmkid, &h80211[z + 105], 16);

							/* copy the key descriptor version */
							st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);

							memcpy(st_cur->wpa.stmac, st_cur->stmac, 6);
							if (!ap_cur->pmkid_logged)
							{
								ap_cur->pmkid_logged = 1;
								memcpy(lopt.wpa_bssid, ap_cur->bssid, 6);
								memset(lopt.message, '\x00', sizeof(lopt.message));
								snprintf(lopt.message,
										sizeof(lopt.message) - 1,
										"][ PMKID found: "
										"%02X:%02X:%02X:%02X:%02X:%02X ",
										lopt.wpa_bssid[0],
										lopt.wpa_bssid[1],
										lopt.wpa_bssid[2],
										lopt.wpa_bssid[3],
										lopt.wpa_bssid[4],
										lopt.wpa_bssid[5]);
								append_tui_message_history_now(lopt.message);
							}

							goto write_packet;
						}
					}
				}
			}

			/* frame 2 or 4: Pairwise == 1, Install == 0, Ack == 0, MIC == 1 */

			if (z + 17 + 32 > (unsigned) caplen) goto write_packet;

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) == 0
				&& (h80211[z + 6] & 0x80) == 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					memcpy(st_cur->wpa.snonce, &h80211[z + 17], 32);
					st_cur->wpa.state |= 2;
				}

				if ((st_cur->wpa.state & 4) != 4)
				{
					st_cur->wpa.eapol_size
						= (uint32_t)((h80211[z + 2] << 8) + h80211[z + 3] + 4);

					if (caplen - z < st_cur->wpa.eapol_size
						|| st_cur->wpa.eapol_size == 0 //-V560
						|| caplen - z < 81 + 16
						|| st_cur->wpa.eapol_size > sizeof(st_cur->wpa.eapol))
					{
						// Ignore the packet trying to crash us.
						st_cur->wpa.eapol_size = 0;
						goto write_packet;
					}

					memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
					memcpy(
						st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
					memset(st_cur->wpa.eapol + 81, 0, 16);
					st_cur->wpa.state |= 4;
					st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
				}
			}

			/* frame 3: Pairwise == 1, Install == 1, Ack == 1, MIC == 1 */

			if ((h80211[z + 6] & 0x08) != 0 && (h80211[z + 6] & 0x40) != 0
				&& (h80211[z + 6] & 0x80) != 0
				&& (h80211[z + 5] & 0x01) != 0)
			{
				if (memcmp(&h80211[z + 17], ZERO, 32) != 0)
				{
					memcpy(st_cur->wpa.anonce, &h80211[z + 17], 32);
					st_cur->wpa.state |= 1;
				}

				if ((st_cur->wpa.state & 4) != 4)
				{
					st_cur->wpa.eapol_size
						= (h80211[z + 2] << 8) + h80211[z + 3] + 4u;

					if (st_cur->wpa.eapol_size == 0 //-V560
						|| st_cur->wpa.eapol_size
							   >= sizeof(st_cur->wpa.eapol) - 16)
					{
						// Ignore the packet trying to crash us.
						st_cur->wpa.eapol_size = 0;
						goto write_packet;
					}

					memcpy(st_cur->wpa.keymic, &h80211[z + 81], 16);
					memcpy(
						st_cur->wpa.eapol, &h80211[z], st_cur->wpa.eapol_size);
					memset(st_cur->wpa.eapol + 81, 0, 16);
					st_cur->wpa.state |= 4;
					st_cur->wpa.keyver = (uint8_t)(h80211[z + 6] & 7);
				}
			}

			if (st_cur->wpa.state == 7 && !is_filtered_essid(ap_cur->essid)
				&& !ap_cur->handshake_logged)
			{
				ap_cur->handshake_logged = 1;
				memcpy(st_cur->wpa.stmac, st_cur->stmac, 6);
				memcpy(lopt.wpa_bssid, ap_cur->bssid, 6);
				memset(lopt.message, '\x00', sizeof(lopt.message));
				snprintf(lopt.message,
						 sizeof(lopt.message) - 1,
						 "][ WPA handshake: %02X:%02X:%02X:%02X:%02X:%02X ",
						 lopt.wpa_bssid[0],
						 lopt.wpa_bssid[1],
						 lopt.wpa_bssid[2],
						 lopt.wpa_bssid[3],
						 lopt.wpa_bssid[4],
						 lopt.wpa_bssid[5]);
				append_tui_message_history_now(lopt.message);

				if (opt.f_ivs != NULL)
				{
					memset(&ivs2, '\x00', sizeof(struct ivs2_pkthdr));
					ivs2.flags = 0;

					ivs2.len = sizeof(struct WPA_hdsk);
					ivs2.flags |= IVS2_WPA;

					if (memcmp(lopt.prev_bssid, ap_cur->bssid, 6) != 0)
					{
						ivs2.flags |= IVS2_BSSID;
						ivs2.len += 6;
						memcpy(lopt.prev_bssid, ap_cur->bssid, 6);
					}

					if (fwrite(&ivs2, 1, sizeof(struct ivs2_pkthdr), opt.f_ivs)
						!= (size_t) sizeof(struct ivs2_pkthdr))
					{
						perror("fwrite(IV header) failed");
						return (EXIT_FAILURE);
					}

					if (ivs2.flags & IVS2_BSSID)
					{
						if (fwrite(ap_cur->bssid, 1, 6, opt.f_ivs)
							!= (size_t) 6)
						{
							perror("fwrite(IV bssid) failed");
							return (EXIT_FAILURE);
						}
						ivs2.len -= 6;
					}

					if (fwrite(&(st_cur->wpa),
							   1,
							   sizeof(struct WPA_hdsk),
							   opt.f_ivs)
						!= (size_t) sizeof(struct WPA_hdsk))
					{
						perror("fwrite(IV wpa_hdsk) failed");
						return (EXIT_FAILURE);
					}
				}
			}
		}
	}

write_packet:

	if (ap_cur != NULL)
	{
		if (h80211[0] == 0x80 && lopt.one_beacon)
		{
			if (!ap_cur->beacon_logged)
				ap_cur->beacon_logged = 1;
			else
				return (0);
		}
	}

	if (opt.record_data)
	{
		if (((h80211[0] & 0x0C) == 0x00) && ((h80211[0] & 0xF0) == 0xB0))
		{
			/* authentication packet */
			check_shared_key(h80211, (size_t) caplen);
		}
	}

	if (ap_cur != NULL)
	{
		if (ap_cur->security != 0 && lopt.f_encrypt != 0
			&& ((ap_cur->security & lopt.f_encrypt) == 0))
		{
			return (1);
		}

		if (is_filtered_essid(ap_cur->essid))
		{
			return (1);
		}
	}

	/* this changes the local ap_cur, st_cur and na_cur variables and should be
	 * the last check before the actual write */
	if (caplen < 24 && caplen >= 10 && h80211[0])
	{
		/* RTS || CTS || ACK || CF-END || CF-END&CF-ACK*/
		//(h80211[0] == 0xB4 || h80211[0] == 0xC4 || h80211[0] == 0xD4 ||
		// h80211[0] == 0xE4 || h80211[0] == 0xF4)

		/* use general control frame detection, as the structure is always the
		 * same: mac(s) starting at [4] */
		if (h80211[0] & 0x04)
		{
			p = h80211 + 4;
			while ((uintptr_t) p <= adds_uptr((uintptr_t) h80211, 16)
				   && (uintptr_t) p <= adds_uptr((uintptr_t) h80211, caplen))
			{
				memcpy(namac, p, 6);

				if (memcmp(namac, NULL_MAC, 6) == 0)
				{
					p += 6;
					continue;
				}

				if (memcmp(namac, BROADCAST, 6) == 0)
				{
					p += 6;
					continue;
				}

				if (lopt.hide_known)
				{
					/* check AP list */
					ap_cur = lopt.ap_1st;

					while (ap_cur != NULL)
					{
						if (!memcmp(ap_cur->bssid, namac, 6)) break;

						ap_cur = ap_cur->next;
					}

					/* if it's an AP, try next mac */

					if (ap_cur != NULL)
					{
						p += 6;
						continue;
					}

					/* check ST list */
					st_cur = lopt.st_1st;

					while (st_cur != NULL)
					{
						if (!memcmp(st_cur->stmac, namac, 6)) break;

						st_cur = st_cur->next;
					}

					/* if it's a client, try next mac */

					if (st_cur != NULL)
					{
						p += 6;
						continue;
					}
				}

				/* not found in either AP list or ST list, look through NA list
				 */
				na_cur = lopt.na_1st;
				na_prv = NULL;

				while (na_cur != NULL)
				{
					if (!memcmp(na_cur->namac, namac, 6)) break;

					na_prv = na_cur;
					na_cur = na_cur->next;
				}

				/* update our chained list of unknown stations */
				/* if it's a new mac, add it */

				if (na_cur == NULL)
				{
					if (!(na_cur
						  = (struct NA_info *) malloc(sizeof(struct NA_info))))
					{
						perror("malloc failed");
						return (1);
					}

					memset(na_cur, 0, sizeof(struct NA_info));

					if (lopt.na_1st == NULL)
						lopt.na_1st = na_cur;
					else
						na_prv->next = na_cur;

					memcpy(na_cur->namac, namac, 6);

					na_cur->prev = na_prv;

					gettimeofday(&(na_cur->tv), NULL);
					na_cur->tinit = time(NULL);
					na_cur->tlast = time(NULL);

					na_cur->power = -1;
					na_cur->channel = -1;
					na_cur->ack = 0;
					na_cur->ack_old = 0;
					na_cur->ackps = 0;
					na_cur->cts = 0;
					na_cur->rts_r = 0;
					na_cur->rts_t = 0;
				}

				/* update the last time seen & power*/

				na_cur->tlast = time(NULL);
				na_cur->power = ri->ri_power;
				na_cur->channel = ri->ri_channel;

				switch (h80211[0] & 0xF0)
				{
					case 0xB0:
						if (p == h80211 + 4) na_cur->rts_r++;
						if (p == h80211 + 10) na_cur->rts_t++;
						break;

					case 0xC0:
						na_cur->cts++;
						break;

					case 0xD0:
						na_cur->ack++;
						break;

					default:
						na_cur->other++;
						break;
				}

				/*grab next mac (for rts frames)*/
				p += 6;
			}
		}
	}

	if (opt.f_cap != NULL && caplen >= 10)
	{

		pkh.len = pkh.caplen = (uint32_t) caplen;

		gettimeofday(&tv, NULL);

		pkh.tv_sec = (int32_t) tv.tv_sec;
		pkh.tv_usec = (int32_t) tv.tv_usec;
		
		if (lopt.ppi) {
			float gpsLat = 0, gpsLon = 0, gpsAlt = 0;
			if (lopt.coordinates[0] != 0 || lopt.coordinates[1] != 0) {
				gpsLat = (float)lopt.coordinates[0];
				gpsLon = (float)lopt.coordinates[1];
				gpsAlt = 0;
			} else {
				// call to calculate ppi header length
				gpsLat = lopt.gps_loc[0];
				gpsLon = lopt.gps_loc[1];
				gpsAlt = lopt.gps_loc[4];
			}
			ppi_header_len = calculate_ppi_header_length(gpsLat, gpsLon, gpsAlt);
			// Update caplen in the packet header
			pkh.len = pkh.caplen = (uint32_t)(caplen + ppi_header_len);
		}

		
		// Allocate memory for full packet (PCAP header + PPI header + packet payload)
		total_packet_size = sizeof(pkh) + ppi_header_len + caplen;
		packet_data = (uint8_t *)malloc(total_packet_size);
		if (!packet_data) {
			perror("malloc failed");
			return 1;
		}

		// Copy PCAP Packet header into packet_data address
		memcpy(packet_data, &pkh, sizeof(pkh));

		n = sizeof(pkh);

		if (fwrite(&pkh, 1, n, opt.f_cap) != (size_t) n)
		{
			perror("fwrite(packet header) failed");
			return (1);
		}

		fflush(stdout);

		if (lopt.ppi) {
			float gpsLat = 0, gpsLon = 0, gpsAlt = 0;
			if (lopt.coordinates[0] != 0.0 || lopt.coordinates[1] != 0.0) {
				// Case 1: User provided command-line coordinates
				gpsLat = (float)lopt.coordinates[0];
				gpsLon = (float)lopt.coordinates[1];
				gpsAlt = 0;

			} else if (lopt.gps_loc[0] != 0.0 || lopt.gps_loc[1] != 0.0) {
				// Case 2: Live GPS data
				gpsLat = (float)lopt.gps_loc[0];
				gpsLon = (float)lopt.gps_loc[1];
				gpsAlt = (float)lopt.gps_loc[4];

				// Save latest valid fix
				last_coordinates[0] = lopt.gps_loc[0];
				last_coordinates[1] = lopt.gps_loc[1];
				last_coordinates[2] = lopt.gps_loc[4];

			} else if (last_coordinates[0] != 0.0 || last_coordinates[1] != 0.0) {
				// Case 3: Fallback to last known good GPS fix
				gpsLat = (float)last_coordinates[0];
				gpsLon = (float)last_coordinates[1];
				gpsAlt = (float)last_coordinates[2];
			}

			uint64_t tsfTimer = ri->ri_mactime; // Time Synchronization Function timer, usually a 64-bit value
			int dataRate = ri->ri_rate / 50000;      // Data rate in Mbps, integer value (e.g., 1 Mbps)
			int freq = getFrequencyFromChannel(ri->ri_channel);       // Frequency in MHz, for 2.4 GHz band channels (e.g., 2412 MHz for channel 1)
			int rssi = ri->ri_power;        // Received Signal Strength Indicator, in dBm (e.g., -50 dBm)
			int noise = ri->ri_noise;      // Noise level in dBm (e.g., -100 dBm)
			write_ppi_headers(opt.f_cap, tsfTimer, dataRate, freq, rssi, noise, gpsLat, gpsLon, gpsAlt);
		}

		if (lopt.tcp_sock_fd > 0) {

			if (lopt.ppi) {
				float gpsLat = 0, gpsLon = 0, gpsAlt = 0;
				if (lopt.coordinates[0] != 0.0 || lopt.coordinates[1] != 0.0) {
					// Case 1: User provided command-line coordinates
					gpsLat = (float)lopt.coordinates[0];
					gpsLon = (float)lopt.coordinates[1];
					gpsAlt = 0;

				} else if (lopt.gps_loc[0] != 0.0 || lopt.gps_loc[1] != 0.0) {
					// Case 2: Live GPS data
					gpsLat = (float)lopt.gps_loc[0];
					gpsLon = (float)lopt.gps_loc[1];
					gpsAlt = (float)lopt.gps_loc[4];

					// Save latest valid fix
					last_coordinates[0] = lopt.gps_loc[0];
					last_coordinates[1] = lopt.gps_loc[1];
					last_coordinates[2] = lopt.gps_loc[4];

				} else if (last_coordinates[0] != 0.0 || last_coordinates[1] != 0.0) {
					// Case 3: Fallback to last known good GPS fix
					gpsLat = (float)last_coordinates[0];
					gpsLon = (float)last_coordinates[1];
					gpsAlt = (float)last_coordinates[2];
				}

				uint64_t tsfTimer = ri->ri_mactime; // Time Synchronization Function timer, usually a 64-bit value
				int dataRate = ri->ri_rate / 50000;      // Data rate in Mbps, integer value (e.g., 1 Mbps)
				int freq = getFrequencyFromChannel(ri->ri_channel);       // Frequency in MHz, for 2.4 GHz band channels (e.g., 2412 MHz for channel 1)
				int rssi = ri->ri_power;        // Received Signal Strength Indicator, in dBm (e.g., -50 dBm)
				int noise = ri->ri_noise;      // Noise level in dBm (e.g., -100 dBm)
				write_ppi_headers_to_buffer(packet_data + sizeof(pkh), tsfTimer, dataRate, freq, rssi, noise, gpsLat, gpsLon, gpsAlt);

			}

			// Copy packet payload
			memcpy(packet_data + sizeof(pkh) + ppi_header_len, h80211, caplen);

			// *** Send over TCP if sockfd is valid ***
			if (lopt.tcp_sock_fd > 0) {
				n = send(lopt.tcp_sock_fd, packet_data, total_packet_size, 0);
				if (n <= 0) {
					if (n == 0) {
						printf("\nClient disconnected gracefully.\n");
					} else {
						perror("\nSend failed, client may have disconnected");
					}
					close(lopt.tcp_sock_fd);  // Close the socket
					lopt.tcp_sock_fd = -1;    // Mark socket as invalid
				}
			}

		}

		//n = pkh.caplen;

		if (fwrite(h80211, 1, caplen, opt.f_cap) != caplen)
		{
			perror("fwrite(packet data) failed");
			return (1);
		}

		fflush(stdout);
	}

	free(packet_data);
	return (0);
}

static void dump_sort(void)
{
	time_t tt = time(NULL);

	/* thanks to Arnaud Cornet :-) */

	struct AP_info * new_ap_1st = NULL;
	struct AP_info * new_ap_end = NULL;

	struct AP_info *ap_cur, *ap_min;

	/* sort the aps by WHATEVER first */

	while (lopt.ap_1st)
	{
		ap_min = NULL;
		ap_cur = lopt.ap_1st;

		while (ap_cur != NULL)
		{
			if (tt - ap_cur->tlast > 20) ap_min = ap_cur;

			ap_cur = ap_cur->next;
		}

		if (ap_min == NULL)
		{
			ap_min = ap_cur = lopt.ap_1st;

			/*#define SORT_BY_BSSID	1
#define SORT_BY_POWER	2
#define SORT_BY_BEACON	3
#define SORT_BY_DATA	4
#define SORT_BY_PRATE	6
#define SORT_BY_CHAN	7
#define	SORT_BY_MBIT	8
#define SORT_BY_ENC	9
#define SORT_BY_CIPHER	10
#define SORT_BY_AUTH	11
#define SORT_BY_ESSID	12*/

			while (ap_cur != NULL)
			{
				switch (lopt.sort_by)
				{
					case SORT_BY_BSSID:
						if (memcmp(ap_cur->bssid, ap_min->bssid, 6)
								* lopt.sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_POWER:
						if ((ap_cur->avg_power - ap_min->avg_power)
								* lopt.sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_BEACON:
						if ((ap_cur->nb_bcn < ap_min->nb_bcn) && lopt.sort_inv)
							ap_min = ap_cur;
						break;
					case SORT_BY_DATA:
						if ((ap_cur->nb_data < ap_min->nb_data)
							&& lopt.sort_inv)
							ap_min = ap_cur;
						break;
					case SORT_BY_PRATE:
						if ((ap_cur->nb_dataps - ap_min->nb_dataps)
								* lopt.sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_CHAN:
						if ((ap_cur->channel - ap_min->channel) * lopt.sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_STAS:
					{
						int lhs_rank = ap_station_count_rank(ap_cur);
						int rhs_rank = ap_station_count_rank(ap_min);

						if ((lhs_rank - rhs_rank) * lopt.sort_inv < 0)
							ap_min = ap_cur;
						break;
					}
					case SORT_BY_MBIT:
						if ((ap_cur->max_speed - ap_min->max_speed)
								* lopt.sort_inv
							< 0)
							ap_min = ap_cur;
						break;
					case SORT_BY_ENC:
					{
						int lhs_rank = ap_security_std_rank(ap_cur->security);
						int rhs_rank = ap_security_std_rank(ap_min->security);

						if ((lhs_rank - rhs_rank) * lopt.sort_inv < 0)
							ap_min = ap_cur;
						break;
					}
					case SORT_BY_CIPHER:
					{
						int lhs_rank = ap_security_cipher_rank(ap_cur->security);
						int rhs_rank = ap_security_cipher_rank(ap_min->security);

						if ((lhs_rank - rhs_rank) * lopt.sort_inv < 0)
							ap_min = ap_cur;
						break;
					}
					case SORT_BY_AUTH:
					{
						int lhs_rank = ap_security_auth_rank(ap_cur->security);
						int rhs_rank = ap_security_auth_rank(ap_min->security);

						if ((lhs_rank - rhs_rank) * lopt.sort_inv < 0)
							ap_min = ap_cur;
						break;
					}
					case SORT_BY_ESSID:
						if (ap_essid_compare(ap_cur, ap_min) * lopt.sort_inv < 0)
							ap_min = ap_cur;
						break;
					default: // sort by power
						if (ap_cur->avg_power < ap_min->avg_power)
							ap_min = ap_cur;
						break;
				}
				ap_cur = ap_cur->next;
			}
		}

		if (ap_min == lopt.ap_1st) lopt.ap_1st = ap_min->next;

		if (ap_min == lopt.ap_end) lopt.ap_end = ap_min->prev;

		if (ap_min->next) ap_min->next->prev = ap_min->prev;

		if (ap_min->prev) ap_min->prev->next = ap_min->next;

		if (new_ap_end)
		{
			new_ap_end->next = ap_min;
			ap_min->prev = new_ap_end;
			new_ap_end = ap_min;
			new_ap_end->next = NULL;
		}
		else
		{
			new_ap_1st = new_ap_end = ap_min;
			ap_min->next = ap_min->prev = NULL;
		}
	}

	lopt.ap_1st = new_ap_1st;
	lopt.ap_end = new_ap_end;
}

static int ap_sort_is_live(int sort_by)
{
	switch (sort_by)
	{
		case SORT_BY_POWER:
		case SORT_BY_BEACON:
		case SORT_BY_DATA:
		case SORT_BY_PRATE:
		case SORT_BY_CHAN:
		case SORT_BY_STAS:
		case SORT_BY_MBIT:
		case SORT_BY_ENC:
		case SORT_BY_CIPHER:
		case SORT_BY_AUTH:
		case SORT_BY_ESSID:
			return (1);
		default:
			return (0);
	}
}

static int getBatteryState(void) { return get_battery_state(); }

static char * getStringTimeFromSec(double seconds)
{
	int hour[3];
	char * ret;
	char * HourTime;
	char * MinTime;

	if (seconds < 0) return (NULL);

	ret = (char *) calloc(1, 256);
	ALLEGE(ret != NULL);

	HourTime = (char *) calloc(1, 128);
	ALLEGE(HourTime != NULL);
	MinTime = (char *) calloc(1, 128);
	ALLEGE(MinTime != NULL);

	hour[0] = (int) (seconds);
	hour[1] = hour[0] / 60;
	hour[2] = hour[1] / 60;
	hour[0] %= 60;
	hour[1] %= 60;

	if (hour[2] != 0)
		snprintf(
			HourTime, 128, "%d %s", hour[2], (hour[2] == 1) ? "hour" : "hours");
	if (hour[1] != 0)
		snprintf(
			MinTime, 128, "%d %s", hour[1], (hour[1] == 1) ? "min" : "mins");

	if (hour[2] != 0 && hour[1] != 0)
		snprintf(ret, 256, "%s %s", HourTime, MinTime);
	else
	{
		if (hour[2] == 0 && hour[1] == 0)
			snprintf(ret, 256, "%d s", hour[0]);
		else
			snprintf(ret, 256, "%s", (hour[2] == 0) ? MinTime : HourTime);
	}

	free(MinTime);
	free(HourTime);

	return (ret);
}

static char * getBatteryString(void)
{
	int batt_time;
	char * ret;
	char * batt_string;

	batt_time = getBatteryState();

	if (batt_time <= 60)
	{
		ret = (char *) calloc(1, 2);
		ALLEGE(ret != NULL);
		ret[0] = ']';
		return (ret);
	}

	batt_string = getStringTimeFromSec((double) batt_time);
	ALLEGE(batt_string != NULL);

	ret = (char *) calloc(1, 256);
	ALLEGE(ret != NULL);

	snprintf(ret, 256, "][ BAT: %s ]", batt_string);

	free(batt_string);

	return (ret);
}

#define TSTP_SEC                                                               \
	1000000ULL /* It's a 1 MHz clock, so a million ticks per second! */
#define TSTP_MIN (TSTP_SEC * 60ULL)
#define TSTP_HOUR (TSTP_MIN * 60ULL)
#define TSTP_DAY (TSTP_HOUR * 24ULL)

static char * parse_timestamp(unsigned long long timestamp)
{
#define TSTP_LEN 15
	static char s[TSTP_LEN];
	unsigned long long rem;
	unsigned char days, hours, mins, secs;

	// Initialize array
	memset(s, 0, TSTP_LEN);

	// Calculate days, hours, mins and secs
	days = (uint8_t)(timestamp / TSTP_DAY);
	rem = timestamp % TSTP_DAY;
	hours = (unsigned char) (rem / TSTP_HOUR);
	rem %= TSTP_HOUR;
	mins = (unsigned char) (rem / TSTP_MIN);
	rem %= TSTP_MIN;
	secs = (unsigned char) (rem / TSTP_SEC);

	snprintf(s, TSTP_LEN, "%3ud %02u:%02u:%02u", days, hours, mins, secs);
#undef TSTP_LEN

	return (s);
}

static int IsAp2BeSkipped(struct AP_info * ap_cur)
{
	REQUIRE(ap_cur != NULL);

	if (ap_cur->nb_pkt < lopt.min_pkts
		|| time(NULL) - ap_cur->tlast > lopt.berlin
		|| memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
	{
		return (1);
	}

	if (ap_cur->security != 0 && lopt.f_encrypt != 0
		&& ((ap_cur->security & lopt.f_encrypt) == 0))
	{
		return (1);
	}

	if (is_filtered_essid(ap_cur->essid))
	{
		return (1);
	}

	return (0);
}

static struct AP_info * find_unassociated_ap(void)
{
	struct AP_info * ap_cur = lopt.ap_end;

	while (ap_cur != NULL)
	{
		if (memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
			return (ap_cur);
		ap_cur = ap_cur->prev;
	}

	return (NULL);
}

static int has_unassociated_clients(void)
{
	struct ST_info * st_cur = lopt.st_1st;

	while (st_cur != NULL)
	{
		if (time(NULL) - st_cur->tlast <= lopt.berlin
			&& st_cur->base != NULL
			&& memcmp(st_cur->base->bssid, BROADCAST, 6) == 0)
		{
			return (1);
		}
		st_cur = st_cur->next;
	}

	return (0);
}

static struct AP_info * find_visible_ap_from_head(void)
{
	struct AP_info * ap_cur = lopt.ap_end;

	while (ap_cur != NULL && IsAp2BeSkipped(ap_cur))
		ap_cur = ap_cur->prev;
	if (ap_cur == NULL && has_unassociated_clients())
		return (find_unassociated_ap());
	return (ap_cur);
}

static struct AP_info * find_visible_ap_from_tail(void)
{
	struct AP_info * ap_cur = lopt.ap_1st;

	while (ap_cur != NULL && IsAp2BeSkipped(ap_cur))
		ap_cur = ap_cur->next;
	if (ap_cur == NULL && has_unassociated_clients())
		return (find_unassociated_ap());
	return (ap_cur);
}

static struct AP_info * find_tui_visible_ap_relative(struct AP_info * current, int direction)
{
	struct AP_info * ap_cur;
	struct AP_info * ap_rows[4096];
	size_t ap_count = 0;
	size_t i;

	if (current == NULL) return (NULL);
	if (direction == 0) return (current);

	ap_cur = lopt.ap_end;
	while (ap_cur != NULL && ap_count < sizeof(ap_rows) / sizeof(ap_rows[0]))
	{
		if (!IsAp2BeSkipped(ap_cur))
			ap_rows[ap_count++] = ap_cur;
		ap_cur = ap_cur->prev;
	}

	if (has_unassociated_clients() && ap_count < sizeof(ap_rows) / sizeof(ap_rows[0]))
	{
		ap_cur = find_unassociated_ap();
		if (ap_cur != NULL)
			ap_rows[ap_count++] = ap_cur;
	}

	for (i = 0; i < ap_count; i++)
	{
		if (ap_rows[i] == current)
		{
			if (direction < 0)
			{
				if (i == 0) return (NULL);
				return (ap_rows[i - 1]);
			}
			if (i + 1 >= ap_count) return (NULL);
			return (ap_rows[i + 1]);
		}
	}

	return (NULL);
}

static void record_tui_message_history(void)
{
	char normalized[sizeof(tui_message_history_last)];

	if (channel_entry_active) return;
	if (!normalize_tui_message(lopt.message, normalized, sizeof(normalized)))
		return;
	if (strstr(normalized, "Are you sure you want to quit? Press Q again to quit.") != NULL)
		return;
	if (strcmp(normalized, tui_message_history_last) == 0) return;

	append_tui_message_history(normalized, time(NULL));
}

static void append_tui_message_history(const char * message, time_t timestamp)
{
	char normalized[sizeof(tui_message_history_last)];

	if (message == NULL || *message == '\0') return;
	if (!normalize_tui_message(message, normalized, sizeof(normalized)))
		return;
	if (strcmp(normalized, tui_message_history_last) == 0) return;

	if (tui_message_history_count == AIRODUMP_TUI_MESSAGE_HISTORY)
	{
		memmove(tui_message_history,
				tui_message_history + 1,
				(AIRODUMP_TUI_MESSAGE_HISTORY - 1) * sizeof(tui_message_history[0]));
		tui_message_history_count = AIRODUMP_TUI_MESSAGE_HISTORY - 1;
	}

	tui_message_history[tui_message_history_count].timestamp = timestamp;
	tui_message_history[tui_message_history_count].style = message_style_from_text(normalized);
	strlcpy(tui_message_history[tui_message_history_count].text,
			normalized,
			sizeof(tui_message_history[tui_message_history_count].text));
	tui_message_history_count++;
	strlcpy(tui_message_history_last, normalized, sizeof(tui_message_history_last));
}

static void append_tui_message_history_now(const char * message)
{
	append_tui_message_history(message, time(NULL));
	if (use_ncurses_tui)
	{
		if (!(tui_state.focus == 2 && !tui_state.msg_follow_latest))
			set_message_follow_latest(1);
		render_output_view(0);
	}
}

static void reset_hopper_reject_state(void)
{
	hopper_reject_count = 0;
	hopper_reject_total = 0;
	hopper_reject_card = -1;
	hopper_reject_value = 0;
	hopper_reject_is_freq = 0;
	hopper_event_pending = 0;
	hopper_refused_count = 0;
}

static void record_hopper_refused_target(int value, int is_freq)
{
	sig_atomic_t i;
	sig_atomic_t count;

	if (value <= 0) return;
	count = hopper_refused_count;
	for (i = 0; i < count; i++)
	{
		if (hopper_refused_values[i] == value
			&& hopper_refused_is_freq[i] == is_freq)
			return;
	}
	if (count >= (sig_atomic_t) ArrayCount(hopper_refused_values))
		return;
	hopper_refused_values[count] = value;
	hopper_refused_is_freq[count] = is_freq;
	hopper_refused_count = count + 1;
}

static int hopper_target_refused(int value, int is_freq)
{
	sig_atomic_t i;
	sig_atomic_t count;

	if (value <= 0) return (0);
	count = hopper_refused_count;
	for (i = 0; i < count; i++)
	{
		if (hopper_refused_values[i] == value
			&& hopper_refused_is_freq[i] == is_freq)
			return (1);
	}
	return (0);
}

static size_t get_allowed_ax_frequencies(int * freqs, size_t max_freqs)
{
	FILE * fp;
	char line[256];
	size_t count = 0;

	if (freqs == NULL || max_freqs == 0) return (0);

	fp = popen("iw list 2>/dev/null", "r");
	if (fp == NULL) return (0);

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char * p = line;
		int freq;
		size_t i;
		int duplicate = 0;

		while (isspace((unsigned char) *p))
			p++;
		if (strncmp(p, "Band ", 5) == 0) continue;

		if (*p != '*') continue;
		p++;
		while (isspace((unsigned char) *p))
			p++;
		if (sscanf(p, "%d", &freq) != 1) continue;
		if (freq < 5925 || freq > 7125) continue;
		if (strstr(line, "(disabled)") != NULL) continue;

		for (i = 0; i < count; i++)
		{
			if (freqs[i] == freq)
			{
				duplicate = 1;
				break;
			}
		}
		if (duplicate) continue;
		freqs[count++] = freq;
		if (count == max_freqs) break;
	}

	pclose(fp);
	return (count);
}

static int ax_frequency_in_hopper_list(int frequency)
{
	int i;

	if (frequency <= 0 || lopt.own_frequencies == NULL) return (0);
	for (i = 0; lopt.own_frequencies[i] != 0; i++)
	{
		if (lopt.own_frequencies[i] == frequency)
			return (1);
	}
	return (0);
}

static int compare_channel_status_entries(const void * lhs, const void * rhs)
{
	const struct airodump_tui_channel_entry * a = lhs;
	const struct airodump_tui_channel_entry * b = rhs;

	if (a->channel != b->channel)
		return (a->channel - b->channel);
	return (a->frequency - b->frequency);
}

static void process_hopper_event(int card, int value)
{
	if (card == -1)
	{
		regdom_refresh_pending = 1;
		return;
	}

	if (card < 0 || (size_t) card >= ArrayCount(lopt.frequency))
		return;

	if (value < 0)
	{
		int refused_value = -value;
		int is_freq = lopt.freqoption ? 1 : 0;

		hopper_reject_card = card;
		hopper_reject_value = refused_value;
		hopper_reject_is_freq = is_freq;
		hopper_reject_count++;
		hopper_reject_seq++;
		hopper_event_pending = 1;
		record_hopper_refused_target(refused_value, is_freq);
	}
	else if (lopt.freqoption)
		lopt.frequency[card] = value;
	else
	{
		lopt.channel[card] = value;
		lopt.frequency[card] = channel_to_frequency(lopt.channel[card]);
	}
}

static size_t build_channel_status_entries(struct airodump_tui_channel_entry * entries,
										   size_t max_entries)
{
	const int * channels;
	size_t count = 0;
	int is_freq = 0;
	int i;

	if (entries == NULL || max_entries == 0) return (0);

	if (lopt.band_mode == BAND_MODE_AX)
	{
		channels = ax_chans;
		is_freq = 1;
	}
	else if (lopt.band_mode == BAND_MODE_A)
		channels = a_chans;
	else if (lopt.band_mode == BAND_MODE_BG)
		channels = bg_chans;
	else
		channels = lopt.channels;

	if (channels == NULL) return (0);

	for (i = 0; channels[i] != 0 && count < max_entries; i++)
	{
		int channel = channels[i];
		int frequency;
		int refused_value;
		int available = 1;

		if (channel < 0) continue;
		if (lopt.band_mode == BAND_MODE_AX)
			frequency = channel_to_frequency_ax(channel);
		else
			frequency = getFrequencyFromChannel(channel);
		if (frequency <= 0)
			frequency = channel_to_frequency(channel);
		refused_value = is_freq ? frequency : channel;
		if (lopt.band_mode == BAND_MODE_AX)
			available = ax_frequency_in_hopper_list(frequency);

		entries[count].channel = channel;
		entries[count].frequency = frequency;
		if (hopper_target_refused(refused_value, is_freq))
			entries[count].status = AIRODUMP_TUI_CHANNEL_STATUS_REFUSED;
		else if (!available)
			entries[count].status = AIRODUMP_TUI_CHANNEL_STATUS_UNAVAILABLE;
		else
			entries[count].status = AIRODUMP_TUI_CHANNEL_STATUS_OK;
		count++;
	}

	qsort(entries, count, sizeof(entries[0]), compare_channel_status_entries);
	return (count);
}

static void update_hopper_reject_message(void)
{
	static sig_atomic_t last_seq = 0;
	sig_atomic_t seq;
	int card;
	int value;
	int is_freq;
	int count;
	int total;
	int remaining;
	int channel = 0;
	char regdom[16];
	char detail[sizeof(lopt.message)];
	const char * ifname = "interface";
	const char * status = "ref";

	seq = hopper_reject_seq;
	if (seq == 0 || seq == last_seq) return;

	card = (int) hopper_reject_card;
	value = (int) hopper_reject_value;
	is_freq = (int) hopper_reject_is_freq;
	count = (int) hopper_reject_count;
	total = (int) hopper_reject_total;
	last_seq = seq;
	if (total < count)
		total = count;
	remaining = total - count;
	if (remaining <= 0 && total > 0)
		status = "blocked";

	if (card >= 0 && g_wi != NULL && card < lopt.num_cards && g_wi[card] != NULL
		&& wi_get_ifname(g_wi[card]) != NULL)
		ifname = wi_get_ifname(g_wi[card]);

	strlcpy(regdom, get_cached_regdom(0), sizeof(regdom));

	if (is_freq)
	{
		channel = getChannelFromFrequency(value);
		if (channel > 0)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ %s %d/%d ch%d %dMHz",
					 status,
					 count,
					 total,
					 channel,
					 value);
			snprintf(detail,
					 sizeof(detail),
					 "][ hopper warning: driver refused %s frequency %d MHz (ch %d) on %s; %d of %d scan target%s rejected, %d remain, regdom %s. Try b/B to switch band",
					 band_mode_label(lopt.band_mode),
					 value,
					 channel,
					 ifname,
					 count,
					 total,
					 count == 1 ? "" : "s",
					 remaining,
					 regdom);
		}
		else
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ %s %d/%d %dMHz",
					 status,
					 count,
					 total,
					 value);
			snprintf(detail,
					 sizeof(detail),
					 "][ hopper warning: driver refused %s frequency %d MHz on %s; %d of %d scan target%s rejected, %d remain, regdom %s. Try b/B to switch band",
					 band_mode_label(lopt.band_mode),
					 value,
					 ifname,
					 count,
					 total,
					 count == 1 ? "" : "s",
					 remaining,
					 regdom);
		}
	}
	else
	{
		int frequency = channel_to_frequency(value);

		if (frequency > 0)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ %s %d/%d ch%d %dMHz",
					 status,
					 count,
					 total,
					 value,
					 frequency);
			snprintf(detail,
					 sizeof(detail),
					 "][ hopper warning: driver refused %s channel %d (%d MHz) on %s; %d of %d scan target%s rejected, %d remain, regdom %s. Try b/B to switch band",
					 band_mode_label(lopt.band_mode),
					 value,
					 frequency,
					 ifname,
					 count,
					 total,
					 count == 1 ? "" : "s",
					 remaining,
					 regdom);
		}
		else
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ %s %d/%d ch%d",
					 status,
					 count,
					 total,
					 value);
			snprintf(detail,
					 sizeof(detail),
					 "][ hopper warning: driver refused %s channel %d on %s; %d of %d scan target%s rejected, %d remain, regdom %s. Try b/B to switch band",
					 band_mode_label(lopt.band_mode),
					 value,
					 ifname,
					 count,
					 total,
					 count == 1 ? "" : "s",
					 remaining,
					 regdom);
		}
	}

	append_tui_message_history(detail, time(NULL));
}

static void set_channel_entry_prompt(void)
{
	snprintf(channel_entry_prompt,
			 sizeof(channel_entry_prompt),
			 "select channel for %s: %s_",
			 band_mode_label(lopt.band_mode),
			 channel_entry_buf);
}

static int get_active_phy_index(void)
{
	const char * ifname = NULL;
	char path[PATH_MAX];
	char phy_name[32];
	FILE * fp;
	int phy = -1;
	size_t len;

	if (g_wi != NULL && g_wi[0] != NULL)
		ifname = wi_get_ifname(g_wi[0]);
	if (ifname == NULL || ifname[0] == '\0')
		ifname = lopt.s_iface;
	if (ifname == NULL || ifname[0] == '\0')
		return (-1);

	len = strcspn(ifname, ",");
	if (len == 0 || len >= 64)
		return (-1);
	snprintf(path,
			 sizeof(path),
			 "/sys/class/net/%.*s/phy80211/name",
			 (int) len,
			 ifname);

	fp = fopen(path, "r");
	if (fp == NULL) return (-1);
	if (fgets(phy_name, sizeof(phy_name), fp) != NULL
		&& sscanf(phy_name, "phy%d", &phy) == 1)
	{
		fclose(fp);
		return (phy);
	}
	fclose(fp);
	return (-1);
}

static int get_kernel_regdom(char * out, size_t out_len)
{
	FILE * fp;
	char line[256];
	char global[16];
	char phy_actual[16];
	int active_phy;
	int current_phy = -2;

	if (out == NULL || out_len == 0) return (0);
	out[0] = '\0';
	global[0] = '\0';
	phy_actual[0] = '\0';
	active_phy = get_active_phy_index();

	fp = popen("iw reg get 2>/dev/null", "r");
	if (fp == NULL) return (0);

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char * p = line;
		int phy;

		while (isspace((unsigned char) *p))
			p++;
		if (strncmp(p, "global", 6) == 0)
		{
			current_phy = -1;
			continue;
		}
		if (sscanf(p, "phy#%d", &phy) == 1)
		{
			current_phy = phy;
			continue;
		}
		if (strncmp(p, "country ", 8) != 0) continue;
		p += 8;
		if (isalnum((unsigned char) p[0]) && isalnum((unsigned char) p[1]))
		{
			char code[3];

			code[0] = (char) toupper((unsigned char) p[0]);
			code[1] = (char) toupper((unsigned char) p[1]);
			code[2] = '\0';
			if (current_phy == active_phy)
				strlcpy(phy_actual, code, sizeof(phy_actual));
			else if (current_phy == -1)
				strlcpy(global, code, sizeof(global));
		}
	}

	pclose(fp);
	if (phy_actual[0] != '\0')
		strlcpy(out, phy_actual, out_len);
	else if (global[0] != '\0')
		strlcpy(out, global, out_len);
	else
		return (0);
	return (1);
}

static void cache_kernel_regdom(const char * regdom)
{
	if (regdom == NULL || regdom[0] == '\0') return;
	strlcpy(cached_regdom, regdom, sizeof(cached_regdom));
	regdom_refresh_pending = 0;
}

static const char * get_cached_regdom(int force_refresh)
{
	char current[16];

	if ((force_refresh || regdom_refresh_pending || cached_regdom[0] == '\0')
		&& get_kernel_regdom(current, sizeof(current)))
	{
		cache_kernel_regdom(current);
	}
	else if (force_refresh || regdom_refresh_pending)
	{
		regdom_refresh_pending = 0;
	}
	if (cached_regdom[0] == '\0')
		strlcpy(cached_regdom, "unknown", sizeof(cached_regdom));
	return (cached_regdom);
}

static void render_output(void)
{
	render_output_view(1);
}

static void render_output_view(int record_message_history)
{
	update_hopper_reject_message();

	if (use_ncurses_tui)
	{
		struct airodump_tui_view view;
		char regdom_label[16];
		struct airodump_tui_channel_entry channel_status[AIRODUMP_TUI_MAX_CHANNEL_STATUS];

		memset(&view, 0, sizeof(view));
		view.ap_1st = lopt.ap_1st;
		view.ap_end = lopt.ap_end;
		view.st_1st = lopt.st_1st;
		view.selected_ap = lopt.p_selected_ap;
		view.f_encrypt = lopt.f_encrypt;
		view.min_pkts = lopt.min_pkts;
		view.berlin = lopt.berlin;
		view.asso_client = lopt.asso_client;
		view.show_ap = lopt.show_ap;
		view.show_sta = lopt.show_sta;
		view.show_ack = lopt.show_ack;
		view.singlechan = lopt.singlechan;
		view.show_uptime = lopt.show_uptime;
		view.show_manufacturer = lopt.show_manufacturer;
		view.show_wps = lopt.show_wps;
		view.freqoption = lopt.freqoption;
		view.show_ax_channels = (lopt.band_mode == BAND_MODE_AX);
		view.band_label = band_mode_label(lopt.band_mode);
		strlcpy(regdom_label, get_cached_regdom(0), sizeof(regdom_label));
		view.regdom_label = regdom_label;
		view.channel_status = channel_status;
		view.channel_status_count = build_channel_status_entries(
			channel_status,
			ArrayCount(channel_status));
		view.num_cards = lopt.num_cards;
		memcpy(view.channel, lopt.channel, sizeof(view.channel));
		memcpy(view.frequency, lopt.frequency, sizeof(view.frequency));
		if (channel_entry_active)
			view.message = channel_entry_prompt;
		else
			view.message = lopt.message;
		view.batt = lopt.batt;
		view.elapsed_time = lopt.elapsed_time;
		view.do_pause = lopt.do_pause;
		view.background_mode = lopt.background_mode;
		view.sort_by = lopt.sort_by;
		view.sort_inv = lopt.sort_inv;

		if (record_message_history)
			record_tui_message_history();
		view.messages = tui_message_history;
		view.message_count = tui_message_history_count;
		airodump_tui_render(&tui_state, &view);
	}
	else
	{
		dump_print(lopt.ws.ws_row, lopt.ws.ws_col, lopt.num_cards);
	}
}

static void restore_terminal(void)
{
	if (use_ncurses_tui)
	{
		airodump_tui_stop(&tui_state);
	}
	else
	{
		reset_term();
		show_cursor();
	}

}

static void set_message_follow_latest(int follow_latest)
{
	tui_state.msg_follow_latest = follow_latest ? 1 : 0;
}

static int tui_message_pane_visible(void)
{
	return (use_ncurses_tui && lopt.show_ap && tui_state.cols >= 90);
}

static void cycle_tui_focus(int direction)
{
	int order[3];
	int count = 0;
	int i;

	if (lopt.show_ap)
		order[count++] = 0;
	if (tui_message_pane_visible())
		order[count++] = 2;
	if (lopt.show_sta)
		order[count++] = 1;
	if (count == 0) return;

	for (i = 0; i < count; i++)
	{
		if (order[i] == tui_state.focus)
		{
			i = (i + direction + count) % count;
			set_tui_focus(order[i]);
			return;
		}
	}

	set_tui_focus(order[0]);
}

static void set_tui_focus(int focus)
{
#ifdef HAVE_NCURSES
	if (!use_ncurses_tui) return;
	if (tui_message_pane_visible())
	{
		if (focus < 0) focus = 0;
		if (focus > 2) focus = 2;
		if (focus == 2 && !tui_message_pane_visible()) focus = 0;
	}
	else if (lopt.show_ap == 1 && lopt.show_sta == 1)
	{
		focus = (focus != 0) ? 1 : 0;
	}
	else
	{
		focus = (lopt.show_sta == 1) ? 1 : 0;
	}
	tui_state.focus = focus;
#else
	UNUSED_PARAM(focus);
#endif
}

static void set_selected_ap(struct AP_info * ap, int selection_direction)
{
	lopt.p_selected_ap = ap;
	lopt.en_selection_direction = selection_direction;
	if (ap != NULL)
		memcpy(lopt.selected_bssid, ap->bssid, 6);
	else
		memset(lopt.selected_bssid, '\x00', 6);
}

static const char * station_sort_field_name(int sort_by)
{
	switch (sort_by)
	{
		case STA_SORT_BY_NOTHING:
			return ("none");
		case STA_SORT_BY_BSSID:
			return ("BSSID");
		case STA_SORT_BY_STATION:
			return ("station MAC");
		case STA_SORT_BY_BAND:
			return ("band");
		case STA_SORT_BY_LA:
			return ("locally administered");
		case STA_SORT_BY_POWER:
			return ("power");
		case STA_SORT_BY_RATE:
			return ("rate");
		case STA_SORT_BY_LOST:
			return ("lost");
		case STA_SORT_BY_FRAMES:
			return ("frames");
		case STA_SORT_BY_NOTES:
			return ("notes");
		case STA_SORT_BY_PROBES:
			return ("probes");
		case STA_SORT_BY_LAST_SEEN:
			return ("last seen");
		default:
			return ("first seen");
	}
}

static int cycle_station_sort_field(int sort_by, int direction)
{
	if (direction == 0) direction = 1;
	if (sort_by < STA_SORT_BY_BSSID || sort_by > STA_SORT_MAX)
		return (STA_SORT_BY_BSSID);
	sort_by += (direction > 0) ? 1 : -1;
	if (sort_by > STA_SORT_MAX)
		sort_by = STA_SORT_BY_BSSID;
	else if (sort_by < STA_SORT_BY_BSSID)
		sort_by = STA_SORT_MAX;
	return (sort_by);
}

static int cycle_ap_sort_field(int sort_by, int direction)
{
	if (direction == 0) direction = 1;
	sort_by += (direction > 0) ? 1 : -1;
	if (sort_by > MAX_SORT)
		sort_by = SORT_BY_NOTHING;
	else if (sort_by < SORT_BY_NOTHING)
		sort_by = MAX_SORT;
	return (sort_by);
}

static int ap_security_std_rank(unsigned int security)
{
	if (security & STD_OPN) return (0);
	if (security & STD_WEP) return (1);
	if (security & STD_WPA) return (2);
	if (security & STD_WPA2)
	{
		if ((security & AUTH_SAE) && (security & AUTH_PSK))
			return (4);
		if (security & AUTH_SAE)
			return (5);
		if (security & AUTH_OWE)
			return (6);
		return (3);
	}
	return (7);
}

static int ap_security_cipher_rank(unsigned int security)
{
	if ((security & ENC_FIELD) == 0) return (0);
	if (security & ENC_WEP) return (1);
	if (security & ENC_WEP40) return (2);
	if (security & ENC_WEP104) return (3);
	if (security & ENC_TKIP) return (4);
	if (security & ENC_CCMP) return (5);
	if (security & ENC_WRAP) return (6);
	if (security & ENC_GCMP) return (7);
	if (security & ENC_GMAC) return (8);
	return (9);
}

static int ap_security_auth_rank(unsigned int security)
{
	if ((security & AUTH_FIELD) == 0) return (0);
	if (security & AUTH_OPN) return (1);
	if ((security & AUTH_SAE) && (security & AUTH_PSK))
		return (3);
	if (security & AUTH_PSK) return (2);
	if (security & AUTH_MGT) return (4);
	if (security & AUTH_CMAC) return (5);
	if (security & AUTH_SAE) return (6);
	if (security & AUTH_OWE) return (7);
	return (8);
}

static const char * ap_security_std_label(unsigned int security)
{
	if (security & STD_WPA2)
	{
		if ((security & AUTH_SAE) && (security & AUTH_PSK))
			return ("WPA2/3");
		if (security & AUTH_SAE)
			return ("WPA3");
		if (security & AUTH_OWE)
			return ("OWE");
		return ("WPA2");
	}
	if (security & STD_WPA) return ("WPA");
	if (security & STD_WEP) return ("WEP");
	if (security & STD_OPN) return ("OPN");
	return ("");
}

static int ap_station_count_rank(const struct AP_info * ap)
{
	if (ap == NULL || ap->bss_load_station_count < 0) return (-1);
	return (ap->bss_load_station_count);
}

static int ap_essid_compare(const struct AP_info * lhs, const struct AP_info * rhs)
{
	size_t lhs_len;
	size_t rhs_len;
	size_t min_len;
	int cmp;

	if (lhs == NULL || rhs == NULL) return (0);

	lhs_len = strnlen((const char *) lhs->essid, ESSID_LENGTH);
	rhs_len = strnlen((const char *) rhs->essid, ESSID_LENGTH);

	if (lhs_len == 0 && rhs_len != 0) return (1);
	if (lhs_len != 0 && rhs_len == 0) return (-1);

	min_len = MIN(lhs_len, rhs_len);
	cmp = strncasecmp((const char *) lhs->essid, (const char *) rhs->essid, min_len);
	if (cmp != 0) return (cmp);

	if (lhs_len != rhs_len) return ((lhs_len < rhs_len) ? -1 : 1);

	cmp = strncasecmp((const char *) lhs->essid, (const char *) rhs->essid, ESSID_LENGTH);
	if (cmp != 0) return (cmp);

	return (memcmp(lhs->bssid, rhs->bssid, 6));
}

static char * csv_escape_field(const unsigned char * input, size_t len)
{
	size_t i;
	size_t out_len = 3; /* quotes + NUL */
	char * out;
	char * cursor;

	if (input == NULL) return (NULL);

	for (i = 0; i < len; i++)
	{
		out_len += 1;
		if (input[i] == '"') out_len++;
	}

	out = (char *) malloc(out_len);
	ALLEGE(out != NULL);

	cursor = out;
	*cursor++ = '"';
	for (i = 0; i < len; i++)
	{
		if (input[i] == '"') *cursor++ = '"';
		*cursor++ = (char) input[i];
	}
	*cursor++ = '"';
	*cursor = '\0';

	return (out);
}

static struct probe_log_entry * find_probe_log_entry(const unsigned char * probe,
													 size_t len)
{
	struct probe_log_entry * entry = probe_log_entries;

	while (entry != NULL)
	{
		if (entry->essid_len == len && memcmp(entry->essid, probe, len) == 0)
			return (entry);
		entry = entry->next;
	}

	return (NULL);
}

static void format_probe_timestamp(char * out, size_t out_len, time_t ts)
{
	struct tm * ltime;

	if (out == NULL || out_len == 0) return;

	ltime = localtime(&ts);
	if (ltime != NULL
		&& strftime(out, out_len, "%Y-%m-%d %H:%M:%S", ltime) > 0)
	{
		return;
	}

	snprintf(out, out_len, "%ld", (long) ts);
}

static void rewrite_probe_log_csv(void)
{
	const struct probe_log_entry * entry;
	char first_seen[32];
	char last_seen[32];
	char * essid_csv;

	if (!opt.output_format_probes || opt.f_probes == NULL) return;

	fflush(opt.f_probes);
	rewind(opt.f_probes);
	if (ftruncate(fileno(opt.f_probes), 0) != 0)
	{
		perror("ftruncate failed");
		return;
	}

	fprintf(opt.f_probes,
			"First seen,Last seen,Station MAC,Times seen,Probe ESSID\r\n");

	entry = probe_log_entries;
	while (entry != NULL)
	{
		format_probe_timestamp(first_seen, sizeof(first_seen), entry->first_seen);
		format_probe_timestamp(last_seen, sizeof(last_seen), entry->last_seen);
		essid_csv = csv_escape_field(entry->essid, entry->essid_len);
		if (essid_csv != NULL)
		{
			fprintf(opt.f_probes,
					"%s,%s,%02X:%02X:%02X:%02X:%02X:%02X,%lu,%s\r\n",
					first_seen,
					last_seen,
					entry->station_mac[0],
					entry->station_mac[1],
					entry->station_mac[2],
					entry->station_mac[3],
					entry->station_mac[4],
					entry->station_mac[5],
					entry->times_seen,
					essid_csv);
			free(essid_csv);
		}
		entry = entry->next;
	}

	fflush(opt.f_probes);
}

static void free_probe_log_entries(void)
{
	struct probe_log_entry * entry = probe_log_entries;

	while (entry != NULL)
	{
		struct probe_log_entry * next = entry->next;
		free(entry);
		entry = next;
	}

	probe_log_entries = NULL;
}

static void log_distinct_probe_essid(const struct ST_info * st_cur,
									 const unsigned char * probe,
									 size_t len)
{
	struct probe_log_entry * entry;
	time_t seen_ts;

	if (st_cur == NULL || probe == NULL || len == 0) return;
	if (!opt.output_format_probes || opt.f_probes == NULL) return;

	seen_ts = (st_cur->tlast != 0) ? st_cur->tlast : time(NULL);
	entry = find_probe_log_entry(probe, len);
	if (entry == NULL)
	{
		entry = (struct probe_log_entry *) calloc(1, sizeof(*entry));
		ALLEGE(entry != NULL);
		entry->next = probe_log_entries;
		probe_log_entries = entry;
		entry->first_seen = seen_ts;
		entry->essid_len = len;
		memcpy(entry->essid, probe, len);
		entry->essid[len] = '\0';
	}

	entry->last_seen = seen_ts;
	entry->times_seen++;
	memcpy(entry->station_mac, st_cur->stmac, sizeof(entry->station_mac));
	rewrite_probe_log_csv();
}

static int deauth_mfp_guard(struct AP_info * ap_cur)
{
	if (ap_cur == NULL) return (0);

	if (ap_cur->mfp_required || (ap_cur->security & AUTH_SAE))
	{
		ap_cur->mfp_warned = 1;
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ Selected AP requires MFP; press d again to continue");
		append_tui_message_history_now(lopt.message);
		return (1);
	}

	if (ap_cur->mfp_capable && !ap_cur->mfp_warned)
	{
		ap_cur->mfp_warned = 1;
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ Selected AP advertises optional MFP; deauth may fail");
		append_tui_message_history_now(lopt.message);
		return (1);
	}

	return (0);
}

static int deauth_is_unassociated_ap(const struct AP_info * ap_cur)
{
	return (ap_cur != NULL && memcmp(ap_cur->bssid, BROADCAST, 6) == 0);
}

static void deauth_refuse_with_message(const char * reason)
{
	snprintf(lopt.message, sizeof(lopt.message), "][ Deauth refused: %s", reason);
	append_tui_message_history_now(lopt.message);
}

static int point_in_box(int x, int y, int top, int left, int height, int width)
{
	return (height > 0 && width > 0 && y >= top && y < top + height
			&& x >= left && x < left + width);
}

static int mouse_target_focus(int x, int y)
{
	if (point_in_box(x,
					 y,
					 tui_state.msg_box_top,
					 tui_state.msg_box_left,
					 tui_state.msg_box_height,
					 tui_state.msg_box_width))
	{
		return (2);
	}
	if (point_in_box(x,
					 y,
					 tui_state.sta_box_top,
					 tui_state.sta_box_left,
					 tui_state.sta_box_height,
					 tui_state.sta_box_width))
	{
		return (1);
	}
	if (point_in_box(x,
					 y,
					 tui_state.ap_box_top,
					 tui_state.ap_box_left,
					 tui_state.ap_box_height,
					 tui_state.ap_box_width))
	{
		return (0);
	}
	return (tui_state.focus);
}

static struct AP_info * pick_ap_from_mouse(int x, int y)
{
	struct AP_info * ap_cur;
	struct AP_info * ap_rows[4096];
	size_t ap_count = 0;
	size_t ap_scroll = 0;
	size_t selected_index = 0;
	size_t i;
	size_t row_index;
	size_t visible_rows;

	if (!use_ncurses_tui || !lopt.show_ap || tui_state.ap_box_width < 1
		|| tui_state.ap_box_height < 1)
	{
		return (NULL);
	}

	if (!point_in_box(x,
					 y,
					 tui_state.ap_box_top,
					 tui_state.ap_box_left,
					 tui_state.ap_box_height,
					 tui_state.ap_box_width))
	{
		return (NULL);
	}

	if (x < tui_state.ap_box_left + 1 || x >= tui_state.ap_box_left + tui_state.ap_box_width - 1)
		return (NULL);
	if (y < tui_state.ap_box_top + 3)
		return (NULL);

	visible_rows = (size_t) tui_state.ap_visible_rows;
	if (visible_rows == 0) return (NULL);

	ap_cur = lopt.ap_end;
	while (ap_cur != NULL)
	{
		if (!IsAp2BeSkipped(ap_cur))
		{
			if (ap_count < sizeof(ap_rows) / sizeof(ap_rows[0]))
				ap_rows[ap_count++] = ap_cur;
		}
		ap_cur = ap_cur->prev;
	}

	if (has_unassociated_clients())
	{
		ap_cur = find_unassociated_ap();
		if (ap_cur != NULL && ap_count < sizeof(ap_rows) / sizeof(ap_rows[0]))
			ap_rows[ap_count++] = ap_cur;
	}

	if (ap_count == 0) return (NULL);

	if (lopt.p_selected_ap != NULL)
	{
		for (i = 0; i < ap_count; i++)
		{
			if (ap_rows[i] == lopt.p_selected_ap)
			{
				selected_index = i;
				break;
			}
		}
	}

	ap_scroll = (size_t) tui_state.ap_scroll;
	if (ap_scroll > ap_count - 1)
		ap_scroll = ap_count - 1;
	if (lopt.p_selected_ap != NULL)
	{
		if (ap_scroll > selected_index)
			ap_scroll = selected_index;
		if (selected_index >= ap_scroll + visible_rows)
			ap_scroll = selected_index - visible_rows + 1;
	}
	if (ap_scroll > ap_count - visible_rows)
		ap_scroll = (ap_count > visible_rows) ? ap_count - visible_rows : 0;

	row_index = (size_t) (y - (tui_state.ap_box_top + 3));
	if (row_index >= visible_rows) return (NULL);
	if (ap_scroll + row_index >= ap_count) return (NULL);

	return (ap_rows[ap_scroll + row_index]);
}

static int handle_mouse_event(void)
{
#ifdef HAVE_NCURSES
	MEVENT event;
	struct AP_info * ap_hit;
	int target_focus;
	int redraw = 0;
	int sort_by;

	if (!use_ncurses_tui) return (0);
	if (getmouse(&event) != OK) return (0);

	if (event.bstate & BUTTON_SHIFT)
		return (0);

	target_focus = mouse_target_focus(event.x, event.y);

	if (event.bstate & (BUTTON4_PRESSED | BUTTON4_CLICKED | BUTTON4_DOUBLE_CLICKED))
	{
		set_tui_focus(target_focus);
		if (target_focus == 1)
		{
			if (tui_state.sta_scroll > 0)
				tui_state.sta_scroll--;
			redraw = 1;
		}
		else if (target_focus == 2)
		{
			if (tui_state.msg_scroll > 0)
				tui_state.msg_scroll--;
			set_message_follow_latest(0);
			redraw = 1;
		}
		else if (tui_state.ap_scroll > 0)
		{
			tui_state.ap_scroll--;
			redraw = 1;
		}
		return (redraw);
	}

	if (event.bstate & (BUTTON5_PRESSED | BUTTON5_CLICKED | BUTTON5_DOUBLE_CLICKED))
	{
		set_tui_focus(target_focus);
		if (target_focus == 1)
		{
			tui_state.sta_scroll++;
			redraw = 1;
		}
		else if (target_focus == 2)
		{
			tui_state.msg_scroll++;
			set_message_follow_latest(0);
			redraw = 1;
		}
		else
		{
			tui_state.ap_scroll++;
			redraw = 1;
		}
		return (redraw);
	}

	if ((event.bstate & BUTTON1_PRESSED) == 0)
	{
		return (0);
	}

	{
		sort_by = airodump_tui_station_sort_field_from_mouse(&tui_state, event.x, event.y);

		if (sort_by != STA_SORT_BY_NOTHING)
		{
			tui_state.sta_sort_by = sort_by;
			tui_state.sta_sort_inv *= -1;
			if (tui_state.sta_sort_inv == 0) tui_state.sta_sort_inv = 1;
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ sorting stations by %s (%s)",
					 station_sort_field_name(tui_state.sta_sort_by),
					 (tui_state.sta_sort_inv < 0) ? "descending" : "ascending");
			set_tui_focus(1);
			redraw = 1;
			return (redraw);
		}
	}

	sort_by = airodump_tui_ap_sort_field_from_mouse(&tui_state, event.x, event.y);
	if (sort_by != SORT_BY_NOTHING)
	{
		lopt.sort_by = sort_by;
		lopt.sort_inv *= -1;
		if (lopt.sort_inv < 0) lopt.sort_inv = -1;
		else lopt.sort_inv = 1;
		ALLEGE(pthread_mutex_lock(&(lopt.mx_sort)) == 0);
		dump_sort();
		ALLEGE(pthread_mutex_unlock(&(lopt.mx_sort)) == 0);
		set_tui_focus(0);
		return (1);
	}

	if (target_focus == 1)
	{
		set_tui_focus(1);
	}

	ap_hit = pick_ap_from_mouse(event.x, event.y);
	if (ap_hit != NULL)
	{
		set_selected_ap(ap_hit, selection_direction_no);
		set_tui_focus(0);
		return (1);
	}

	if (point_in_box(event.x,
					 event.y,
					 tui_state.ap_box_top,
					 tui_state.ap_box_left,
					 tui_state.ap_box_height,
					 tui_state.ap_box_width))
	{
		if (event.y >= tui_state.ap_box_top + 3)
		{
			set_selected_ap(NULL, selection_direction_no);
			set_tui_focus(0);
			return (1);
		}
		set_tui_focus(0);
		return (1);
	}

	if (point_in_box(event.x,
					 event.y,
					 tui_state.msg_box_top,
					 tui_state.msg_box_left,
					 tui_state.msg_box_height,
					 tui_state.msg_box_width))
	{
		set_tui_focus(2);
		return (1);
	}

	if (point_in_box(event.x,
					 event.y,
					 tui_state.sta_box_top,
					 tui_state.sta_box_left,
					 tui_state.sta_box_height,
					 tui_state.sta_box_width))
	{
		set_tui_focus(1);
		return (1);
	}
#endif

	return (0);
}

static int handle_keycode(int keycode)
{
	int redraw = 0;

	if (keycode == KEY_MOUSE)
	{
		if (handle_mouse_event())
			redraw = 1;
		goto done;
	}

	if (channel_entry_active)
	{
		if (keycode == 27 || keycode == KEY_ESCAPE)
		{
			cancel_channel_entry("][ channel entry cancelled");
			redraw = 1;
			goto done;
		}

		if (keycode == '\n' || keycode == '\r' || keycode == KEY_ENTER)
		{
			if (apply_channel_entry())
			{
				redraw = 1;
			}
			else
			{
				redraw = 1;
			}
			goto done;
		}

		if (keycode == KEY_BACKSPACE || keycode == 127 || keycode == 8)
		{
			if (channel_entry_len > 0)
			{
				channel_entry_buf[--channel_entry_len] = '\0';
				set_channel_entry_prompt();
				if (use_ncurses_tui)
					render_output_view(0);
			}
			goto done;
		}

		if (isdigit((unsigned char) keycode))
		{
			if (channel_entry_len < sizeof(channel_entry_buf) - 1)
			{
				channel_entry_buf[channel_entry_len++] = (char) keycode;
				channel_entry_buf[channel_entry_len] = '\0';
				set_channel_entry_prompt();
				if (use_ncurses_tui)
					render_output_view(0);
			}
		}
		goto done;
	}

	if (use_ncurses_tui && tui_state.help_visible)
	{
		tui_state.help_visible = 0;
		redraw = 1;
		goto done;
	}

	if (use_ncurses_tui && tui_state.channel_overlay_visible)
	{
		if (keycode == 'v' || keycode == 27 || keycode == KEY_ESCAPE)
		{
			tui_state.channel_overlay_visible = 0;
			redraw = 1;
			goto done;
		}
		tui_state.channel_overlay_visible = 0;
		redraw = 1;
		goto done;
	}

	if (keycode == '?' || keycode == KEY_F(1))
	{
		if (use_ncurses_tui)
		{
			tui_state.help_visible = !tui_state.help_visible;
			tui_state.channel_overlay_visible = 0;
			redraw = 1;
		}
		goto done;
	}

	if (keycode == 'v')
	{
		if (use_ncurses_tui)
		{
			tui_state.channel_overlay_visible = !tui_state.channel_overlay_visible;
			tui_state.help_visible = 0;
			redraw = 1;
		}
		goto done;
	}

	if (keycode == KEY_q)
	{
		quitting_event_ts = time(NULL);

		if (++quitting > 1) //-V1051
			lopt.do_exit = 1;
		else
			snprintf(
				lopt.message,
				sizeof(lopt.message),
				"][ Are you sure you want to quit? Press Q again to quit.");
		redraw = 1;
	}

	if (keycode == KEY_o)
	{
		if (use_ncurses_tui)
			tui_state.colors_enabled = !tui_state.colors_enabled;
		else if (colors_enabled)
			color_off();
		else
			color_on();
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ color %s",
				 (use_ncurses_tui ? tui_state.colors_enabled : colors_enabled) ? "on" : "off");
		redraw = 1;
	}

	if (keycode == KEY_s || keycode == 'S')
	{
		int direction = (keycode == 'S') ? -1 : 1;

		if (use_ncurses_tui && tui_state.focus == 1)
		{
			tui_state.sta_sort_by = cycle_station_sort_field(tui_state.sta_sort_by, direction);
			tui_state.sta_sort_inv *= -1;
			if (tui_state.sta_sort_inv == 0) tui_state.sta_sort_inv = 1;
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ sorting stations by %s (%s)",
					 station_sort_field_name(tui_state.sta_sort_by),
					 (tui_state.sta_sort_inv < 0) ? "descending" : "ascending");
		}
		else
		{
			lopt.sort_by = cycle_ap_sort_field(lopt.sort_by, direction);
			lopt.sort_inv *= -1;
			if (lopt.sort_inv == 0) lopt.sort_inv = 1;
			ALLEGE(pthread_mutex_lock(&(lopt.mx_sort)) == 0);
			dump_sort();
			ALLEGE(pthread_mutex_unlock(&(lopt.mx_sort)) == 0);
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ sorting APs (%s)",
					 (lopt.sort_inv < 0) ? "descending" : "ascending");
		}
		redraw = 1;
	}

	if (keycode == KEY_SPACE)
	{
		lopt.do_pause = (lopt.do_pause + 1) % 2;
		if (lopt.do_pause)
		{
			snprintf(lopt.message, sizeof(lopt.message), "][ paused output");
			ALLEGE(pthread_mutex_lock(&(lopt.mx_print)) == 0);

			render_output();

			ALLEGE(pthread_mutex_unlock(&(lopt.mx_print)) == 0);
		}
		else
			snprintf(lopt.message, sizeof(lopt.message), "][ resumed output");
		redraw = 1;
	}

	if (keycode == KEY_r)
	{
		resume_hopper();
		redraw = 1;
	}

	if (keycode == 'M')
	{
		if (use_ncurses_tui)
		{
			airodump_tui_set_mouse_enabled(&tui_state, !tui_state.mouse_enabled);
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ mouse capture %s",
					 tui_state.mouse_enabled ? "enabled" : "disabled");
			redraw = 1;
		}
	}

	if (keycode == 't')
	{
		begin_channel_entry();
		goto done;
	}

	if (keycode == 'l')
	{
		if (lock_selected_ap_channel())
			redraw = 1;
		goto done;
	}

	if (keycode == 'w')
	{
		write_wpa_snapshot();
		redraw = 1;
	}

	if (keycode == 'b' || keycode == 'B')
	{
		if (switch_band(keycode == 'B' ? -1 : 1))
			redraw = 1;
	}

	if (keycode == 'R')
	{
		lopt.do_sort_always = (lopt.do_sort_always + 1) % 2;
		if (lopt.do_sort_always)
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ realtime sorting activated");
		else
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ realtime sorting deactivated");
		redraw = 1;
	}

	if (keycode == KEY_d)
	{
		deauth_event_ts = time(NULL);

		if (lopt.p_selected_ap != NULL && deauth_is_unassociated_ap(lopt.p_selected_ap))
		{
			deauth_launching = 0;
			deauth_refuse_with_message("Don't be silly");
			redraw = 1;
			goto done;
		}

		if (++deauth_launching > 1) //-V1051
		{
			deauth_launching = 0;
			launch_deauth();
			redraw = 1;
		}
		else
		{
			if (lopt.p_selected_ap != NULL
				&& (lopt.p_selected_ap->mfp_required
					|| (lopt.p_selected_ap->security & AUTH_SAE)
					|| (lopt.p_selected_ap->mfp_capable
						&& !lopt.p_selected_ap->mfp_warned)))
			{
				deauth_mfp_guard(lopt.p_selected_ap);
			}
			else
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ Are you sure you want to deauth? Press d again to continue.");
			}
			redraw = 1;
		}
	}

	if (keycode == KEY_ARROW_DOWN)
	{
		if (!use_ncurses_tui && tui_state.focus == 1)
		{
			tui_state.sta_scroll++;
			redraw = 1;
		}
		else if (!use_ncurses_tui && tui_state.focus == 2)
		{
			tui_state.msg_scroll++;
			if ((size_t) tui_state.msg_scroll
				>= (tui_message_history_count > (size_t) tui_state.msg_visible_rows
						? tui_message_history_count - (size_t) tui_state.msg_visible_rows
						: 0))
				set_message_follow_latest(1);
			else
				set_message_follow_latest(0);
			redraw = 1;
		}
		else if (!use_ncurses_tui && lopt.p_selected_ap && lopt.p_selected_ap->prev)
		{
			set_selected_ap(lopt.p_selected_ap->prev, selection_direction_down);
			redraw = 1;
		}
	}

	if (keycode == KEY_ARROW_UP)
	{
		if (!use_ncurses_tui && tui_state.focus == 1)
		{
			if (tui_state.sta_scroll > 0) tui_state.sta_scroll--;
			redraw = 1;
		}
		else if (!use_ncurses_tui && tui_state.focus == 2)
		{
			if (tui_state.msg_scroll > 0) tui_state.msg_scroll--;
			set_message_follow_latest(0);
			redraw = 1;
		}
		else if (!use_ncurses_tui && lopt.p_selected_ap && lopt.p_selected_ap->next)
		{
			set_selected_ap(lopt.p_selected_ap->next, selection_direction_up);
			redraw = 1;
		}
	}

	if (keycode == KEY_i)
	{
		if (use_ncurses_tui && tui_state.focus == 1)
		{
			tui_state.sta_sort_inv *= -1;
			if (tui_state.sta_sort_inv < 0)
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ inverted station sorting order");
			else
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ normal station sorting order");
		}
		else
		{
			lopt.sort_inv *= -1;
			if (lopt.sort_inv < 0)
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ inverted sorting order");
			else
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ normal sorting order");
		}
		redraw = 1;
	}

	if (keycode == KEY_TAB)
	{
		if (use_ncurses_tui)
		{
			cycle_tui_focus(1);
			redraw = 1;
		}
		else if (lopt.p_selected_ap == NULL)
		{
			set_selected_ap(lopt.ap_end, selection_direction_down);
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ enabled AP selection");
			lopt.sort_by = SORT_BY_NOTHING;
			redraw = 1;
		}
		else
		{
			set_selected_ap(NULL, selection_direction_no);
			lopt.sort_by = SORT_BY_NOTHING;
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ disabled selection");
			redraw = 1;
		}
	}

	if (keycode == KEY_a)
	{
		if (use_ncurses_tui)
		{
			if (lopt.show_ap == 1 && lopt.show_sta == 1)
			{
				lopt.show_sta = 0;
				tui_state.focus = 0;
				snprintf(lopt.message, sizeof(lopt.message), "][ display ap only");
			}
			else if (lopt.show_ap == 1 && lopt.show_sta == 0)
			{
				lopt.show_ap = 0;
				lopt.show_sta = 1;
				tui_state.focus = 1;
				snprintf(lopt.message, sizeof(lopt.message), "][ display sta only");
			}
			else
			{
				lopt.show_ap = 1;
				lopt.show_sta = 1;
				tui_state.focus = 0;
				snprintf(lopt.message, sizeof(lopt.message), "][ display ap+sta");
			}
			redraw = 1;
		}
		else if (lopt.show_ap == 1 && lopt.show_sta == 1 && lopt.show_ack == 0)
		{
			lopt.show_ack = 1;
			snprintf(lopt.message, sizeof(lopt.message), "][ display ap+sta+ack");
			redraw = 1;
		}
		else if (lopt.show_ap == 1 && lopt.show_sta == 1 && lopt.show_ack == 1)
		{
			lopt.show_sta = 0;
			lopt.show_ack = 0;
			snprintf(lopt.message, sizeof(lopt.message), "][ display ap only");
			redraw = 1;
		}
		else if (lopt.show_ap == 1 && lopt.show_sta == 0 && lopt.show_ack == 0)
		{
			lopt.show_ap = 0;
			lopt.show_sta = 1;
			snprintf(lopt.message, sizeof(lopt.message), "][ display sta only");
			redraw = 1;
		}
		else if (lopt.show_ap == 0 && lopt.show_sta == 1 && lopt.show_ack == 0)
		{
			lopt.show_ap = 1;
			snprintf(lopt.message, sizeof(lopt.message), "][ display ap+sta");
			redraw = 1;
		}
	}

	if (keycode == KEY_c)
	{
		if (use_ncurses_tui)
		{
			set_selected_ap(NULL, selection_direction_no);
			tui_state.ap_scroll = 0;
			tui_state.sta_scroll = 0;
			tui_state.msg_scroll = 0;
			tui_state.focus = 0;
		}
		else
		{
			resetSelection();
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ reset selection to default");
		}
		redraw = 1;
	}

done:

#ifdef HAVE_NCURSES
	if (use_ncurses_tui)
	{
		if (keycode == KEY_LEFT)
		{
			cycle_tui_focus(-1);
			redraw = 1;
		}
		if (keycode == KEY_RIGHT)
		{
			cycle_tui_focus(1);
			redraw = 1;
		}
		if (keycode == KEY_RESIZE)
		{
			tui_resize_pending = 1;
			redraw = 1;
		}
		if (keycode == KEY_UP)
		{
			if (tui_state.focus == 1)
			{
				if (tui_state.sta_scroll > 0) tui_state.sta_scroll--;
				redraw = 1;
			}
			else if (tui_state.focus == 2)
			{
				if (tui_state.msg_scroll > 0) tui_state.msg_scroll--;
				set_message_follow_latest(0);
				redraw = 1;
			}
			else if (lopt.p_selected_ap != NULL)
			{
				struct AP_info * next_ap = find_tui_visible_ap_relative(lopt.p_selected_ap, -1);

				if (next_ap != NULL)
				{
					set_selected_ap(next_ap, selection_direction_up);
					redraw = 1;
				}
			}
			else
			{
				struct AP_info * next_ap = find_visible_ap_from_tail();

				if (next_ap != NULL)
				{
					set_selected_ap(next_ap, selection_direction_up);
					redraw = 1;
				}
			}
		}
		if (keycode == KEY_DOWN)
		{
			if (tui_state.focus == 1)
			{
				tui_state.sta_scroll++;
				redraw = 1;
			}
			else if (tui_state.focus == 2)
			{
				tui_state.msg_scroll++;
				if ((size_t) tui_state.msg_scroll
					>= (tui_message_history_count > (size_t) tui_state.msg_visible_rows
							? tui_message_history_count - (size_t) tui_state.msg_visible_rows
							: 0))
					set_message_follow_latest(1);
				else
					set_message_follow_latest(0);
				redraw = 1;
			}
			else if (lopt.p_selected_ap != NULL)
			{
				struct AP_info * prev_ap = find_tui_visible_ap_relative(lopt.p_selected_ap, 1);

				if (prev_ap != NULL)
				{
					set_selected_ap(prev_ap, selection_direction_down);
					redraw = 1;
				}
			}
			else
			{
				struct AP_info * prev_ap = find_visible_ap_from_head();

				if (prev_ap != NULL)
				{
					set_selected_ap(prev_ap, selection_direction_down);
					redraw = 1;
				}
			}
		}
		if (keycode == KEY_PPAGE)
		{
			if (tui_state.focus == 1)
			{
				tui_state.sta_scroll -= MAX(1, tui_state.sta_visible_rows);
				if (tui_state.sta_scroll < 0) tui_state.sta_scroll = 0;
			}
			else if (tui_state.focus == 2)
			{
				tui_state.msg_scroll -= MAX(1, tui_state.msg_visible_rows);
				if (tui_state.msg_scroll < 0) tui_state.msg_scroll = 0;
				set_message_follow_latest(0);
			}
			else
			{
				tui_state.ap_scroll -= MAX(1, tui_state.ap_visible_rows);
				if (tui_state.ap_scroll < 0) tui_state.ap_scroll = 0;
			}
			redraw = 1;
		}
		if (keycode == KEY_NPAGE)
		{
			if (tui_state.focus == 1)
				tui_state.sta_scroll += MAX(1, tui_state.sta_visible_rows);
			else if (tui_state.focus == 2)
			{
				tui_state.msg_scroll += MAX(1, tui_state.msg_visible_rows);
				if ((size_t) tui_state.msg_scroll
					>= (tui_message_history_count > (size_t) tui_state.msg_visible_rows
							? tui_message_history_count - (size_t) tui_state.msg_visible_rows
							: 0))
					set_message_follow_latest(1);
				else
					set_message_follow_latest(0);
			}
			else
				tui_state.ap_scroll += MAX(1, tui_state.ap_visible_rows);
			redraw = 1;
		}
		if (keycode == KEY_HOME)
		{
			if (tui_state.focus == 1)
				tui_state.sta_scroll = 0;
			else if (tui_state.focus == 2)
			{
				tui_state.msg_scroll = 0;
				set_message_follow_latest(0);
			}
			else
			{
				set_selected_ap(find_visible_ap_from_head(), selection_direction_no);
				tui_state.ap_scroll = 0;
			}
			redraw = 1;
		}
		if (keycode == KEY_END)
		{
			if (tui_state.focus == 1)
				tui_state.sta_scroll = INT_MAX / 4;
			else if (tui_state.focus == 2)
			{
				tui_state.msg_scroll = INT_MAX / 4;
				set_message_follow_latest(1);
			}
			else
				set_selected_ap(find_visible_ap_from_tail(), selection_direction_no);
			redraw = 1;
		}
	}
#endif

	return (redraw);
}

#define CHECK_END_OF_SCREEN()                                                  \
	do                                                                         \
	{                                                                          \
		++nlines;                                                              \
		if (nlines >= (ws_row - 1))                                            \
		{                                                                      \
			erase_display(0);                                                  \
			return;                                                            \
		};                                                                     \
	} while (0)

static void dump_print(int ws_row, int ws_col, int if_num)
{
	time_t tt;
	struct tm * lt;
	int nlines, i, n;
	char strbuf[1024];
	char buffer[1024];
	char ssid_list[512];
	struct AP_info * ap_cur;
	struct ST_info * st_cur;
	struct NA_info * na_cur;
	int columns_ap = 83;
	int columns_sta = 74;
	ssize_t len;

	int num_ap;
	int num_sta;

	if (!lopt.singlechan) columns_ap -= 4; // no RXQ in scan mode
	if (lopt.show_uptime) columns_ap += 15; // show uptime needs more space

	nlines = 2;

	if (nlines >= ws_row) return;

	if (lopt.do_sort_always || ap_sort_is_live(lopt.sort_by))
	{
		ALLEGE(pthread_mutex_lock(&(lopt.mx_sort)) == 0);
		dump_sort();
		ALLEGE(pthread_mutex_unlock(&(lopt.mx_sort)) == 0);
	}

	tt = time(NULL);
	lt = localtime(&tt);

	if (lopt.is_berlin)
	{
		lopt.maxaps = 0;
		lopt.numaps = 0;
		ap_cur = lopt.ap_end;

		while (ap_cur != NULL)
		{
			lopt.maxaps++;
			if (ap_cur->nb_pkt < 2 || time(NULL) - ap_cur->tlast > lopt.berlin
				|| memcmp(ap_cur->bssid, BROADCAST, 6) == 0)
			{
				ap_cur = ap_cur->prev;
				continue;
			}
			lopt.numaps++;
			ap_cur = ap_cur->prev;
		}

		if (lopt.numaps > lopt.maxnumaps) lopt.maxnumaps = lopt.numaps;
	}

	/*
	 *  display the channel, battery, position (if we are connected to GPSd)
	 *  and current time
	 */

	memset(strbuf, '\0', sizeof(strbuf));

	moveto(1, 2);
	textcolor_normal();
	textcolor_fg(TEXT_WHITE);

	if (lopt.freqoption)
	{
		snprintf(strbuf,
				 sizeof(strbuf) - 1,
				 lopt.band_mode == BAND_MODE_AX ? " CH %2d" : " Freq %4d",
				 lopt.band_mode == BAND_MODE_AX ? frequency_to_channel(lopt.frequency[0])
												 : lopt.frequency[0]);
		for (i = 1; i < if_num; i++)
		{
			memset(buffer, '\0', sizeof(buffer));
			snprintf(buffer,
					 sizeof(buffer),
					 lopt.band_mode == BAND_MODE_AX ? ",%2d" : ",%4d",
					 lopt.band_mode == BAND_MODE_AX ? frequency_to_channel(lopt.frequency[i])
													 : lopt.frequency[i]);
			strlcat(strbuf, buffer, sizeof(strbuf));
		}
	}
	else
	{
		snprintf(strbuf, sizeof(strbuf) - 1, " CH %2d", lopt.channel[0]);
		for (i = 1; i < if_num; i++)
		{
			memset(buffer, '\0', sizeof(buffer));
			snprintf(buffer, sizeof(buffer) - 1, ",%2d", lopt.channel[i]);
			strlcat(strbuf, buffer, sizeof(strbuf));
		}
	}
	memset(buffer, '\0', sizeof(buffer));

	if (lopt.gps_loc[0] || (opt.usegpsd))
	{
		// If using GPS then check if we have a valid fix or not and report accordingly
		if (lopt.gps_loc[0] != 0) //-V550
		{
			struct tm * gtime = &lopt.gps_time;
			snprintf(buffer,
					 sizeof(buffer) - 1,
					 " %s[ GPS %3.6f,%3.6f %02d:%02d:%02d ][ Elapsed: %s ][ "
					 "%04d-%02d-%02d %02d:%02d ",
					 lopt.batt,
					 lopt.gps_loc[0],
					 lopt.gps_loc[1],
					 gtime->tm_hour,
					 gtime->tm_min,
					 gtime->tm_sec,
					 lopt.elapsed_time,
					 1900 + lt->tm_year,
					 1 + lt->tm_mon,
					 lt->tm_mday,
					 lt->tm_hour,
					 lt->tm_min);
		}
		else
		{
			snprintf(
				buffer,
				sizeof(buffer) - 1,
				" %s[ GPS %-29s ][ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
				lopt.batt,
				" *** No Fix! ***",
				lopt.elapsed_time,
				1900 + lt->tm_year,
				1 + lt->tm_mon,
				lt->tm_mday,
				lt->tm_hour,
				lt->tm_min);
		}
	}
	else
	{
		snprintf(buffer,
				 sizeof(buffer) - 1,
				 " %s[ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
				 lopt.batt,
				 lopt.elapsed_time,
				 1900 + lt->tm_year,
				 1 + lt->tm_mon,
				 lt->tm_mday,
				 lt->tm_hour,
				 lt->tm_min);
	}

	strlcat(strbuf, buffer, sizeof(strbuf));
	memset(buffer, '\0', sizeof(buffer));

	if (lopt.is_berlin)
	{
		snprintf(buffer,
				 sizeof(buffer) - 1,
				 " ][%3d/%3d/%4d ",
				 lopt.numaps,
				 lopt.maxnumaps,
				 lopt.maxaps);
	}

	strlcat(strbuf, buffer, sizeof(strbuf));
	memset(buffer, '\0', sizeof(buffer));

	if (*lopt.message != '\0')
	{
		strlcat(strbuf, lopt.message, sizeof(strbuf));
	}

	strbuf[ws_col - 1] = '\0';

	ALLEGE(strchr(strbuf, '\n') == NULL);
	console_puts(strbuf);
	CHECK_END_OF_SCREEN();

	/* print some information about each detected AP */

	erase_line(0);
	move(CURSOR_DOWN, 1);
	CHECK_END_OF_SCREEN();

	if (lopt.show_ap)
	{
		strbuf[0] = 0;
		strlcat(strbuf, " BSSID              PWR ", sizeof(strbuf));

		if (lopt.singlechan) strlcat(strbuf, "RXQ ", sizeof(strbuf));

		strlcat(strbuf,
				" Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ",
				sizeof(strbuf));

		if (lopt.show_uptime)
			strlcat(strbuf, "        UPTIME ", sizeof(strbuf));

		if (lopt.show_wps)
		{
			strlcat(strbuf, "WPS   ", sizeof(strbuf));
			if (ws_col > (columns_ap - 4))
			{
				const size_t n_strbuf = strlen(strbuf);
				memset(strbuf + n_strbuf, 32, sizeof(strbuf) - n_strbuf - 1);
				snprintf(strbuf + columns_ap + lopt.maxsize_wps_seen - 5,
						 8,
						 "%s",
						 "  ESSID");
				if (lopt.show_manufacturer)
				{
					memset(strbuf + columns_ap + lopt.maxsize_wps_seen + 1,
						   32,
						   sizeof(strbuf) - columns_ap - lopt.maxsize_wps_seen
							   - 1);
					snprintf(strbuf + columns_ap + lopt.maxsize_wps_seen
								 + lopt.maxsize_essid_seen
								 - 4,
							 15,
							 "%s",
							 "MANUFACTURER");
				}
			}
		}
		else
		{
			strlcat(strbuf, "ESSID", sizeof(strbuf));

			if (lopt.show_manufacturer && (ws_col > (columns_ap - 4)))
			{
				// write spaces (32).
				memset(strbuf + columns_ap, 32, lopt.maxsize_essid_seen - 5);
				snprintf(strbuf + columns_ap + lopt.maxsize_essid_seen - 7,
						 15,
						 "%s",
						 "  MANUFACTURER");
			}
		}
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();

		ap_cur = lopt.ap_end;

		num_ap = 0;

		while (ap_cur != NULL)
		{
			/* skip APs with only one packet, or those older than 2 min.
		* always skip if bssid == broadcast */
			if (IsAp2BeSkipped(ap_cur))
			{
				if (lopt.p_selected_ap == ap_cur)
				{ //the selected AP is skipped (will not be printed), we have to go to the next printable AP
					struct AP_info * ap_tmp;
					if (selection_direction_up
						== lopt.en_selection_direction) //UP arrow was last pressed
					{
						ap_tmp = ap_cur->next;
						if (ap_tmp)
						{
							while ((0 != (lopt.p_selected_ap = ap_tmp))
								   && IsAp2BeSkipped(ap_tmp))
								ap_tmp = ap_tmp->next;
						}
						if (!ap_tmp) //we have reached the first element in the list, so go in another direction
						{ //upon we have an AP that is not skipped
							ap_tmp = ap_cur->prev;
							if (ap_tmp)
							{
								while ((0 != (lopt.p_selected_ap = ap_tmp))
									   && IsAp2BeSkipped(ap_tmp))
									ap_tmp = ap_tmp->prev;
							}
						}
					}
					else if (
						selection_direction_down
						== lopt.en_selection_direction) //DOWN arrow was last pressed
					{
						ap_tmp = ap_cur->prev;
						if (ap_tmp)
						{
							while ((0 != (lopt.p_selected_ap = ap_tmp))
								   && IsAp2BeSkipped(ap_tmp))
								ap_tmp = ap_tmp->prev;
						}
						if (!ap_tmp) //we have reached the last element in the list, so go in another direction
						{ //upon we have an AP that is not skipped
							ap_tmp = ap_cur->next;
							if (ap_tmp)
							{
								while ((0 != (lopt.p_selected_ap = ap_tmp))
									   && IsAp2BeSkipped(ap_tmp))
									ap_tmp = ap_tmp->next;
							}
						}
					}
				}
				ap_cur = ap_cur->prev;
				continue;
			}

			num_ap++;

			if (num_ap < lopt.start_print_ap)
			{
				ap_cur = ap_cur->prev;
				continue;
			}

			nlines++;

			if (nlines > (ws_row - 1)) return;
			
			if (isTargetMAC(ap_cur->bssid)) {
				if (!(ap_cur->marked)) {
					ap_cur->marked = 1;
					ap_cur->marked_color = TEXT_RED;
				}
			}

			memset(strbuf, '\0', sizeof(strbuf));

			snprintf(strbuf,
					 sizeof(strbuf),
					 " %02X:%02X:%02X:%02X:%02X:%02X",
					 ap_cur->bssid[0],
					 ap_cur->bssid[1],
					 ap_cur->bssid[2],
					 ap_cur->bssid[3],
					 ap_cur->bssid[4],
					 ap_cur->bssid[5]);

			len = strlen(strbuf);

			if (lopt.singlechan)
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 "  %3d %3d %8lu %8lu %4d",
						 ap_cur->avg_power,
						 ap_cur->rx_quality,
						 ap_cur->nb_bcn,
						 ap_cur->nb_data,
						 ap_cur->nb_dataps);
			}
			else
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 "  %3d %8lu %8lu %4d",
						 ap_cur->avg_power,
						 ap_cur->nb_bcn,
						 ap_cur->nb_data,
						 ap_cur->nb_dataps);
			}

			len = strlen(strbuf);

			if (ap_cur->standard[0])
			{
				// In case of 802.11n or 802.11ac, QoS is pretty much implied
				// Short or long preamble is not that useful anymore.
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 " %3d %4d   ",
						 ap_cur->channel,
						 ap_cur->max_speed);
			}
			else
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 " %3d %4d%c%c ",
						 ap_cur->channel,
						 ap_cur->max_speed,
						 (ap_cur->security & STD_QOS) ? 'e' : ' ',
						 (ap_cur->preamble) ? '.' : ' ');
			}

			len = strlen(strbuf);

			if ((ap_cur->security & (STD_FIELD | AUTH_SAE | AUTH_OWE)) == 0)
				snprintf(strbuf + len, sizeof(strbuf) - len, "    ");
			else
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 "%-6s",
						 ap_security_std_label(ap_cur->security));
			}

			strlcat(strbuf, " ", sizeof(strbuf));

			len = strlen(strbuf);

			if ((ap_cur->security & ENC_FIELD) == 0)
				snprintf(strbuf + len, sizeof(strbuf) - len, "       ");
			else
			{
				if (ap_cur->security & ENC_CCMP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "CCMP   ");
				else if (ap_cur->security & ENC_WRAP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WRAP   ");
				else if (ap_cur->security & ENC_TKIP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "TKIP   ");
				else if (ap_cur->security & ENC_WEP104)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WEP104 ");
				else if (ap_cur->security & ENC_WEP40)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WEP40  ");
				else if (ap_cur->security & ENC_WEP)
					snprintf(strbuf + len, sizeof(strbuf) - len, "WEP    ");
			}

			len = strlen(strbuf);

			if ((ap_cur->security & AUTH_FIELD) == 0)
				snprintf(strbuf + len, sizeof(strbuf) - len, "       ");
			else
			{
				if ((ap_cur->security & AUTH_SAE) && (ap_cur->security & AUTH_PSK))
					snprintf(strbuf + len, sizeof(strbuf) - len, "PSK+SAE");
				else if (ap_cur->security & AUTH_SAE)
					snprintf(strbuf + len, sizeof(strbuf) - len, "SAE ");
				else if (ap_cur->security & AUTH_MGT)
					snprintf(strbuf + len, sizeof(strbuf) - len, "MGT ");
				else if (ap_cur->security & AUTH_CMAC)
					snprintf(strbuf + len, sizeof(strbuf) - len, "CMAC");
				else if (ap_cur->security & AUTH_PSK)
				{
					if (ap_cur->security & STD_WEP)
						snprintf(strbuf + len, sizeof(strbuf) - len, "SKA ");
					else
						snprintf(strbuf + len, sizeof(strbuf) - len, "PSK ");
				}
				else if (ap_cur->security & AUTH_OWE)
					snprintf(strbuf + len, sizeof(strbuf) - len, "OWE ");
				else if (ap_cur->security & AUTH_OPN)
					snprintf(strbuf + len, sizeof(strbuf) - len, "OPN ");
			}

			len = strlen(strbuf);

			if (lopt.show_uptime)
			{
				snprintf(strbuf + len,
						 sizeof(strbuf) - len,
						 " %14s",
						 parse_timestamp(ap_cur->timestamp));
				len = strlen(strbuf);
			}

			if (lopt.p_selected_ap && (lopt.p_selected_ap == ap_cur))
			{
				textstyle(TEXT_REVERSE);
				memcpy(lopt.selected_bssid, ap_cur->bssid, 6);
			}

			if (ap_cur->marked)
			{
				textcolor_fg(ap_cur->marked_color);
			}

			memset(strbuf + len, 32, sizeof(strbuf) - len - 1);

			if (ws_col > (columns_ap - 4))
			{
				if (lopt.show_wps)
				{
					ssize_t wps_len = len;

					if (ap_cur->wps.state != 0xFF)
					{
						if (ap_cur->wps.ap_setup_locked) // AP setup locked
							snprintf(
								strbuf + len, sizeof(strbuf) - len, "Locked");
						else
						{
							snprintf(strbuf + len,
									 sizeof(strbuf) - len,
									 " %u.%d",
									 ap_cur->wps.version >> 4,
									 ap_cur->wps.version & 0xF); // Version
							len = strlen(strbuf);
							if (ap_cur->wps.meth) // WPS Config Methods
							{
								char tbuf[64];
								memset(tbuf, '\0', sizeof(tbuf));
								int sep = 0;
#define T(bit, name)                                                           \
	do                                                                         \
	{                                                                          \
		if (ap_cur->wps.meth & (1u << (bit)))                                  \
		{                                                                      \
			if (sep) strlcat(tbuf, ",", sizeof(tbuf));                         \
			sep = 1;                                                           \
			strlcat(tbuf, (name), sizeof(tbuf));                               \
		}                                                                      \
	} while (0)
								T(0u, "USB"); // USB method
								T(1u, "ETHER"); // Ethernet
								T(2u, "LAB"); // Label
								T(3u, "DISP"); // Display
								T(4u, "EXTNFC"); // Ext. NFC Token
								T(5u, "INTNFC"); // Int. NFC Token
								T(6u, "NFCINTF"); // NFC Interface
								T(7u, "PBC"); // Push Button
								T(8u, "KPAD"); // Keypad
								snprintf(strbuf + len,
										 sizeof(strbuf) - len,
										 " %s",
										 tbuf);
#undef T
							}
						}
					}
					else
					{
						snprintf(strbuf + len, sizeof(strbuf) - len, " ");
					}
					len = strlen(strbuf);

					if ((ssize_t) lopt.maxsize_wps_seen <= len - wps_len)
						lopt.maxsize_wps_seen = (u_int) MAX(len - wps_len, 6);
					else
					{
						// pad output
						memset(strbuf + len, 32, sizeof(strbuf) - len - 1);
						len += lopt.maxsize_wps_seen - (len - wps_len);
						strbuf[len] = '\0';
					}
				}

				ssize_t essid_len = len;

				if (ap_cur->essid[0] != 0x00)
				{
					if (lopt.show_wps)
						snprintf(strbuf + len,
								 sizeof(strbuf) - len - 1,
								 "  %s",
								 ap_cur->essid);
					else
						snprintf(strbuf + len,
								 sizeof(strbuf) - len,
								 " %s",
								 ap_cur->essid);
				}
				else
				{
					if (lopt.show_wps)
						snprintf(strbuf + len,
								 sizeof(strbuf) - len - 1,
								 "  <length:%3d>%s",
								 ap_cur->ssid_length,
								 "\x00");
					else
						snprintf(strbuf + len,
								 sizeof(strbuf) - len,
								 " <length:%3d>%s",
								 ap_cur->ssid_length,
								 "\x00");
				}
				len = strlen(strbuf);

				if (lopt.show_manufacturer)
				{
					if (lopt.maxsize_essid_seen <= (u_int)(len - essid_len))
						lopt.maxsize_essid_seen
							= (u_int) MAX(len - essid_len, 5);
					else
					{
						// pad output
						memset(strbuf + len, 32, sizeof(strbuf) - len - 1);
						len += lopt.maxsize_essid_seen - (len - essid_len);
						strbuf[len] = '\0';
					}

					if (ap_cur->manuf == NULL)
						ap_cur->manuf = get_manufacturer(ap_cur->bssid[0],
														 ap_cur->bssid[1],
														 ap_cur->bssid[2]);

					snprintf(strbuf + len,
							 sizeof(strbuf) - len - 1,
							 " %s",
							 ap_cur->manuf);
				}
			}

			len = strlen(strbuf);

			// write spaces (32) until the end of column
			int len_remaining = ws_col - len;
			if (len_remaining > 0)
			{
				ALLEGE((size_t) len + len_remaining <= sizeof(strbuf));
				memset(strbuf + len, 32, len_remaining);
			}

			strbuf[ws_col - 1] = '\0';
			console_puts(strbuf);

			if ((lopt.p_selected_ap && (lopt.p_selected_ap == ap_cur))
				|| (ap_cur->marked))
			{
				textstyle(TEXT_RESET);
			}

			if (lopt.target) {
				textcolor_fg(TEXT_WHITE);
			}

			ap_cur = ap_cur->prev;
		}

		/* print some information about each detected station */

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();
	}

	if (lopt.show_sta)
	{
		strlcpy(strbuf,
				" BSSID              STATION  LA "
				"        PWR   Rate    Lost    Frames  Notes  Probes",
				sizeof(strbuf));
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();

		ap_cur = lopt.ap_end;

		num_sta = 0;

		while (ap_cur != NULL)
		{


			if (ap_cur->nb_pkt < 2 || time(NULL) - ap_cur->tlast > lopt.berlin)
			{
				ap_cur = ap_cur->prev;
				continue;
			}

			if (ap_cur->security != 0 && lopt.f_encrypt != 0
				&& ((ap_cur->security & lopt.f_encrypt) == 0))
			{
				ap_cur = ap_cur->prev;
				continue;
			}

			// Don't filter unassociated clients by ESSID
			if (memcmp(ap_cur->bssid, BROADCAST, 6) != 0
				&& is_filtered_essid(ap_cur->essid))
			{
				ap_cur = ap_cur->prev;
				continue;
			}

			if (nlines >= (ws_row - 1)) return;

			st_cur = lopt.st_end;

			if (lopt.p_selected_ap
				&& (memcmp(lopt.selected_bssid, ap_cur->bssid, 6) == 0))
			{
				textstyle(TEXT_REVERSE);
			}

			if (ap_cur->marked)
			{
				textcolor_fg(ap_cur->marked_color);
			}

			while (st_cur != NULL)
			{
				if (st_cur->base != ap_cur
					|| time(NULL) - st_cur->tlast > lopt.berlin)
				{
					st_cur = st_cur->prev;
					continue;
				}

				if (!memcmp(ap_cur->bssid, BROADCAST, 6) && lopt.asso_client)
				{
					st_cur = st_cur->prev;
					continue;
				}

				num_sta++;

				if (lopt.start_print_sta > num_sta) continue;

				nlines++;

				if (nlines >= (ws_row - 1)) return;

				if (isTargetMAC(st_cur->stmac)) {
					if (!(st_cur->marked)) {
						st_cur->marked = 1;
						st_cur->marked_color = TEXT_RED;
					}
				}

				if (st_cur->marked)
				{
					textcolor_fg(st_cur->marked_color);
				}

				if (!memcmp(ap_cur->bssid, BROADCAST, 6))
					printf(" (not associated) ");
				else
					printf(" %02X:%02X:%02X:%02X:%02X:%02X",
						   ap_cur->bssid[0],
						   ap_cur->bssid[1],
						   ap_cur->bssid[2],
						   ap_cur->bssid[3],
						   ap_cur->bssid[4],
						   ap_cur->bssid[5]);

				printf("  %2s", (st_cur->stmac[0] & 0x02) ? "LA" : "");
				printf("  %02X:%02X:%02X:%02X:%02X:%02X",
					   st_cur->stmac[0],
					   st_cur->stmac[1],
					   st_cur->stmac[2],
					   st_cur->stmac[3],
					   st_cur->stmac[4],
					   st_cur->stmac[5]);

				printf("  %3d ", st_cur->power);
				printf("  %2d", st_cur->rate_to / 1000000);
				printf("%c", (st_cur->qos_fr_ds) ? 'e' : ' ');
				printf("-%2d", st_cur->rate_from / 1000000);
				printf("%c", (st_cur->qos_to_ds) ? 'e' : ' ');
				printf("  %4d", st_cur->missed);
				printf(" %8lu", st_cur->nb_pkt);
				printf("  %-5s",
					   (st_cur->wpa.pmkid[0] != 0)
						   ? "PMKID"
						   : (st_cur->wpa.state == 7 ? "EAPOL" : ""));

				if (ws_col > (columns_sta - 6))
				{
					memset(ssid_list, 0, sizeof(ssid_list));

					for (i = 0, n = 0; i < NB_PRB; i++)
					{
						if (st_cur->probes[i][0] == '\0') continue;

						snprintf(ssid_list + n,
								 sizeof(ssid_list) - n - 1,
								 "%c%s",
								 (i > 0) ? ',' : ' ',
								 st_cur->probes[i]);

						n += (1 + strlen(st_cur->probes[i]));

						if (n >= (int) sizeof(ssid_list)) break;
					}

					memset(strbuf, 0, sizeof(strbuf));
					snprintf(strbuf, sizeof(strbuf) - 1, "%-256s", ssid_list)
							< 0
						? abort()
						: (void) 0;
					strbuf[MAX(ws_col - 75, 0)] = '\0';
					printf(" %s", strbuf);
				}

				erase_line(0);
				putchar('\n');

				if (lopt.target) {
					textcolor_fg(TEXT_WHITE);
				}

				st_cur = st_cur->prev;
				
			}

			if ((lopt.p_selected_ap
				 && (memcmp(lopt.selected_bssid, ap_cur->bssid, 6) == 0))
				|| (ap_cur->marked))
			{
				textstyle(TEXT_RESET);
			}

			if (lopt.target) {
				textcolor_fg(TEXT_WHITE);
			}

			ap_cur = ap_cur->prev;
		}
	}

	if (lopt.show_ack)
	{
		/* print some information about each unknown station */

		erase_line(0);
		move(CURSOR_DOWN, 1);
		CHECK_END_OF_SCREEN();

		strlcpy(strbuf,
				" MAC       "
				"          CH PWR    ACK ACK/s    CTS RTS_RX RTS_TX  OTHER",
				sizeof(strbuf));
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		memset(strbuf, ' ', (size_t) ws_col - 1);
		strbuf[ws_col - 1] = '\0';
		console_puts(strbuf);
		CHECK_END_OF_SCREEN();

		na_cur = lopt.na_1st;

		while (na_cur != NULL)
		{
			if (time(NULL) - na_cur->tlast > 120)
			{
				na_cur = na_cur->next;
				continue;
			}

			nlines++;

			if (nlines >= (ws_row - 1)) return;

			printf(" %02X:%02X:%02X:%02X:%02X:%02X",
				   na_cur->namac[0],
				   na_cur->namac[1],
				   na_cur->namac[2],
				   na_cur->namac[3],
				   na_cur->namac[4],
				   na_cur->namac[5]);

			printf("  %3d", na_cur->channel);
			printf(" %3d", na_cur->power);
			printf(" %6d", na_cur->ack);
			printf("  %4d", na_cur->ackps);
			printf(" %6d", na_cur->cts);
			printf(" %6d", na_cur->rts_r);
			printf(" %6d", na_cur->rts_t);
			printf(" %6d", na_cur->other);

			erase_line(0);
			putchar('\n');

			na_cur = na_cur->next;
		}
	}

	erase_display(0);
}

#define OUI_STR_SIZE 8
#define MANUF_SIZE 128
static char *
get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2)
{
	char oui[OUI_STR_SIZE + 1];
	char *manuf, *rmanuf;
	char * manuf_str;
	struct oui * ptr;
	FILE * fp;
	char buffer[BUFSIZ];
	char temp[OUI_STR_SIZE + 1];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	int found = 0;
	size_t oui_len;

	if ((manuf = (char *) calloc(1, MANUF_SIZE * sizeof(char))) == NULL)
	{
		perror("calloc failed");
		return (NULL);
	}

	snprintf(oui, sizeof(oui), "%02X:%02X:%02X", mac0, mac1, mac2);
	oui_len = strlen(oui);

	if (lopt.manufList != NULL)
	{
		// Search in the list
		ptr = lopt.manufList;
		while (ptr != NULL)
		{
			found = !strncasecmp(ptr->id, oui, OUI_STR_SIZE);
			if (found)
			{
				memcpy(manuf, ptr->manuf, MANUF_SIZE);
				break;
			}
			ptr = ptr->next;
		}
	}
	else
	{
		// If the file exist, then query it each time we need to get a
		// manufacturer.
		fp = open_oui_file();

		if (fp != NULL)
		{

			memset(buffer, 0x00, sizeof(buffer));
			while (fgets(buffer, sizeof(buffer), fp) != NULL)
			{
				if (strstr(buffer, "(hex)") == NULL)
				{
					continue;
				}

				memset(a, 0x00, sizeof(a));
				memset(b, 0x00, sizeof(b));
				memset(c, 0x00, sizeof(c));
				if (sscanf(buffer,
						   "%2c-%2c-%2c",
						   (char *) a,
						   (char *) b,
						   (char *) c)
					== 3)
				{
					snprintf(temp,
							 sizeof(temp),
							 "%c%c:%c%c:%c%c",
							 a[0],
							 a[1],
							 b[0],
							 b[1],
							 c[0],
							 c[1]);
					found = !memcmp(temp, oui, oui_len);
					if (found)
					{
						manuf_str = get_manufacturer_from_string(buffer);
						if (manuf_str != NULL)
						{
							snprintf(manuf, MANUF_SIZE, "%s", manuf_str);
							free(manuf_str);
						}

						break;
					}
				}
				memset(buffer, 0x00, sizeof(buffer));
			}

			fclose(fp);
		}
	}

	// Not found, use "Unknown".
	if (!found || *manuf == '\0')
	{
		memcpy(manuf, "Unknown", 7);
		manuf[7] = '\0';
	}

	// Going in a smaller buffer
	rmanuf = (char *) realloc(manuf, (strlen(manuf) + 1) * sizeof(char));
	ALLEGE(rmanuf != NULL);

	return (rmanuf);
}
#undef OUI_STR_SIZE
#undef MANUF_SIZE

/* Read at least one full line from the network.
 *
 * Returns the amount of data in the buffer on success, 0 on connection
 * closed, or a negative value on error.
 *
 * If the return value is >0, the buffer contains at least one newline
 * character.  If the return value is <= 0, the contents of the buffer
 * are undefined.
 */
static inline ssize_t
read_line(int sock, char * buffer, size_t pos, size_t size)
{
	ssize_t status = 1;
	if (size < 1 || pos >= size || buffer == NULL || sock < 0)
	{
		return (-1);
	}

	while (strchr_n(buffer, 0x0A, pos) == NULL && status > 0 && pos < size)
	{
		status = recv(sock, buffer + pos, size - pos, 0);
		if (status > 0)
		{
			pos += status;
		}
	}

	if (status <= 0)
	{
		return (status);
	}
	else if (pos == size && strchr_n(buffer, 0x0A, pos) == NULL)
	{
		return (-1);
	}

	return (pos);
}

/* Extract a name:value pair from a null-terminated line of JSON.
 *
 * Returns 1 if the name was found, or 0 otherwise.
 *
 * The string in "value" is null-terminated if the name was found.  If
 * the name was not found, the contents of "value" are undefined.
 */
static int
json_get_value_for_name(const char * buffer, const char * name, char * value)
{
	char * to_find;
	char * cursor;
	size_t to_find_len;
	char * vcursor = value;
	int ret = 0;

	if (buffer == NULL || *buffer == '\0' || name == NULL || *name == '\0'
		|| value == NULL)
	{
		return (0);
	}

	to_find_len = strlen(name) + 3;
	to_find = (char *) malloc(to_find_len);
	ALLEGE(to_find != NULL);
	snprintf(to_find, to_find_len, "\"%s\"", name);
	cursor = strstr(buffer, to_find);
	free(to_find);
	if (cursor != NULL)
	{
		cursor += to_find_len - 1;
		while (*cursor != ':' && *cursor != '\0')
		{
			cursor++;
		}
		if (*cursor != '\0')
		{
			cursor++;
			while (isspace((int) (*cursor)) && *cursor != '\0')
			{
				cursor++;
			}
		}
		if ('\0' == *cursor)
		{
			return (0);
		}

		if ('"' == *cursor)
		{
			/* Quoted string */
			cursor++;
			while (*cursor != '"' && *cursor != '\0')
			{
				if ('\\' == *cursor && '"' == *(cursor + 1))
				{
					/* Escaped quote */
					*vcursor = '"';
					cursor++;
				}
				else
				{
					*vcursor = *cursor;
				}
				vcursor++;
				cursor++;
			}
			*vcursor = '\0';
			ret = 1;
		}
		else if (strncmp(cursor, "true", 4) == 0)
		{
			/* Boolean */
			strcpy(value, "true");
			ret = 1;
		}
		else if (strncmp(cursor, "false", 5) == 0)
		{
			/* Boolean */
			strcpy(value, "false");
			ret = 1;
		}
		else if ('{' == *cursor || '[' == *cursor)
		{
			/* Object or array.  Too hard to handle and not needed for
			 * getting coords from GPSD, so pretend we didn't see anything.
			 */
			ret = 0;
		}
		else
		{
			/* Number, supposedly.  Copy as-is. */
			while (*cursor != ',' && *cursor != '}'
				   && !isspace((int) (*cursor)))
			{
				*vcursor = *cursor;
				cursor++;
				vcursor++;
			}
			*vcursor = '\0';
			ret = 1;
		}
	}

	return (ret);
}

static THREAD_ENTRY(gps_tracker_thread)
{
	int gpsd_sock = -1;
	char line[1537], buffer[1537], data[1537];
	char * temp;
	struct sockaddr_in gpsd_addr;
	int is_json;
	ssize_t pos;
	int gpsd_tried_connection = 0;
	fd_set read_fd;
	struct timeval timeout;

	(void) arg;

	int * return_success = malloc(sizeof(int));
	ALLEGE(return_success != NULL);
	int * return_error = malloc(sizeof(int));
	ALLEGE(return_error != NULL);

	*return_success = 0;
	*return_error = -1;

	// Incase we GPSd goes down or we lose connection or a fix, we keep trying to connect inside the while loop
	while (lopt.do_exit == 0)
	{
		// If our socket connection to GPSD has been attempted and failed wait before trying again - used to prevent locking the CPU on socket retries
		if (gpsd_tried_connection)
		{
			sleep(2);
		}
		gpsd_tried_connection = 1;

		time_t updateTime = time(NULL);
		memset(line, 0, sizeof(line));
		memset(buffer, 0, sizeof(buffer));
		memset(data, 0, sizeof(data));

		/* attempt to connect to localhost, port 2947 */
		pos = 0;
		if (gpsd_sock >= 0)
		{
			close(gpsd_sock);
		}
		gpsd_sock = socket(AF_INET, SOCK_STREAM, 0);
		if (gpsd_sock < 0) continue;

		memset(&gpsd_addr, 0, sizeof(struct sockaddr_in));
		gpsd_addr.sin_family = AF_INET;
		gpsd_addr.sin_port = htons(2947);
		gpsd_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		if (connect(
				gpsd_sock, (struct sockaddr *) &gpsd_addr, sizeof(gpsd_addr))
			< 0)
			continue;

		// Check if it's GPSd < 2.92 or the new one
		// 2.92+ immediately sends version information
		// < 2.92 requires to send PVTAD command
		FD_ZERO(&read_fd);
		FD_SET(gpsd_sock, &read_fd); // NOLINT(hicpp-signed-bitwise)
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		is_json = select(gpsd_sock + 1, &read_fd, NULL, NULL, &timeout);

		if (is_json > 0)
		{
			/* Probably JSON.  Read the first line and verify it's a version of the
			* protocol we speak. */
			if ((pos = read_line(gpsd_sock, buffer, 0, sizeof(buffer))) <= 0)
				continue;

			pos = get_line_from_buffer(buffer, (size_t) pos, line);
			is_json = (json_get_value_for_name(line, "class", data)
					   && strncmp(data, "VERSION", 7) == 0);

			if (is_json)
			{
				/* Verify it's a version of the protocol we speak */
				if (json_get_value_for_name(line, "proto_major", data)
					&& data[0] != '3')
				{
					/* It's an unknown version of the protocol.  Bail out. */
					continue;
				}

				// Send ?WATCH={"json":true};
				memset(line, 0, sizeof(line));
				strcpy(line, "?WATCH={\"json\":true};\n");
				if (send(gpsd_sock, line, 22, 0) != 22) continue;
			}
		}
		else if (is_json < 0)
		{
			/* An error occurred while we were waiting for data */
			continue;
		}
		/* Else select() returned zero (timeout expired) and we assume we're
		* connected to an old-style gpsd. */

		// Initialisation of all GPS data to 0
		memset(lopt.gps_loc, 0, sizeof(lopt.gps_loc));

		/* Inside loop for reading the GPS coordinates/data */
		while (lopt.do_exit == 0)
		{
			gpsd_tried_connection = 0; // reset socket connection test
			usleep(500000);

			// Reset all GPS data before each read so that if we lose GPS signal
			// or drop to a 2D fix, the loss of data is accurately reflected
			// gps_loc data structure:
			// 0 = lat, 1 = lon, 2 = speed, 3 = heading, 4 = alt, 5 = lat error, 6 = lon error, 7 = vertical error

			// Check if we need to reset/invalidate our GPS data if the data has become 'stale' based on a timeout/interval
			if (time(NULL) - updateTime > lopt.gps_valid_interval)
			{
				memset(lopt.gps_loc, 0, sizeof(lopt.gps_loc));
			}

			// Record ALL GPS data from GPSD
			if (opt.record_data)
			{
				fputs(line, opt.f_gps);
			}

			/* read position, speed, heading, altitude */
			if (is_json)
			{
				// Format definition: http://catb.org/gpsd/gpsd_json.html

				if ((pos = read_line(
						 gpsd_sock, buffer, (size_t) pos, sizeof(buffer)))
					<= 0)
					break;
				pos = get_line_from_buffer(buffer, (size_t) pos, line);

				// See if we got a TPV report - aka actual GPS data if not send default 0 values
				if (!json_get_value_for_name(line, "class", data)
					|| strncmp(data, "TPV", 3) != 0)
				{
					/* Not a TPV report.  Get another line. */

					continue;
				}

				/* See what sort of GPS fix we got.  Possibilities are:
				* 0: No data
				* 1: No fix
				* 2: Lat/Lon, but no alt
				* 3: Lat/Lon/Alt
				* Either 2 or 3 may also have speed and heading data.
				*/
				if (!json_get_value_for_name(line, "mode", data)
					|| (strtol(data, NULL, 10)) < 2)
				{
					/* No GPS fix, so there are no coordinates to extract. */
					continue;
				}

				/* Extract the available data from the TPV report.  If we're
				* in mode 2, latitude and longitude are mandatory, altitude
				* is set to 0, and speed and heading are optional.
				* In mode 3, latitude, longitude, and altitude are mandatory,
				* while speed and heading are optional.
				* If we can't get a mandatory value, the line is discarded
				* as fragmentary or malformed.  If we can't get an optional
				* value, we default it to 0.
				*/

				// GPS Time
				if (json_get_value_for_name(line, "time", data))
				{
					if (!(strptime(data, "%Y-%m-%dT%H:%M:%S", &lopt.gps_time)
						  == NULL))
					{
						updateTime = time(NULL);
					}
				}

				// Latitude
				if (json_get_value_for_name(line, "lat", data))
				{
					lopt.gps_loc[0] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[0] = 0;
					}
				}

				// Longitude
				if (json_get_value_for_name(line, "lon", data))
				{
					lopt.gps_loc[1] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[1] = 0;
					}
				}

				// Longitude Error
				if (json_get_value_for_name(line, "epx", data))
				{
					lopt.gps_loc[6] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[6] = 0;
					}
				}

				// Latitude Error
				if (json_get_value_for_name(line, "epy", data))
				{
					lopt.gps_loc[5] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[5] = 0;
					}
				}

				// Vertical Error
				if (json_get_value_for_name(line, "epv", data))
				{
					lopt.gps_loc[7] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[7] = 0;
					}
				}

				// Altitude
				if (json_get_value_for_name(line, "alt", data))
				{
					lopt.gps_loc[4] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[4] = 0;
					}
				}

				// Speed
				if (json_get_value_for_name(line, "speed", data))
				{
					lopt.gps_loc[2] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[2] = 0;
					}
				}

				// Heading
				if (json_get_value_for_name(line, "track", data))
				{
					lopt.gps_loc[3] = strtof(data, NULL);
					if (errno == EINVAL || errno == ERANGE)
					{
						lopt.gps_loc[3] = 0;
					}
				}
			}
			else
			{
				// Else read a NON JSON format

				memset(line, 0, sizeof(line));

				strcat(line, "PVTAD\r\n");
				if (send(gpsd_sock, line, 7, 0) != 7)
				{
					free(return_success);
					return (return_error);
				}

				memset(line, 0, sizeof(line));
				if (recv(gpsd_sock, line, sizeof(line) - 1, 0) <= 0)
				{
					free(return_success);
					return (return_error);
				}

				if (memcmp(line, "GPSD,P=", 7) != 0) continue;

				/* make sure the coordinates are present */

				if (line[7] == '?') continue;

				int ret;
				updateTime = time(NULL);
				ret = sscanf(line + 7,
							 "%f %f",
							 &lopt.gps_loc[0],
							 &lopt.gps_loc[1]); /* lat lon */
				if (ret == EOF) fprintf(stderr, "Failed to parse lat lon.\n");

				if ((temp = strstr(line, "V=")) == NULL) continue;
				ret = sscanf(temp + 2, "%f", &lopt.gps_loc[2]); /* speed */
				if (ret == EOF) fprintf(stderr, "Failed to parse speed.\n");

				if ((temp = strstr(line, "T=")) == NULL) continue;
				ret = sscanf(temp + 2, "%f", &lopt.gps_loc[3]); /* heading */
				if (ret == EOF) fprintf(stderr, "Failed to parse heading.\n");

				if ((temp = strstr(line, "A=")) == NULL) continue;
				ret = sscanf(temp + 2, "%f", &lopt.gps_loc[4]); /* altitude */
				if (ret == EOF) fprintf(stderr, "Failed to parse altitude.\n");
			}

			lopt.save_gps = 1;
		}

		// If we are still wanting to read GPS but encountered an error - reset data and try again
		if (lopt.do_exit == 0)
		{
			memset(lopt.gps_loc, 0, sizeof(lopt.gps_loc));
			sleep(1);
		}
	}

	free(return_error);
	return (return_success);
}

static void sighandler(int signum)
{
	int card = 0;
	int value = 0;

	if (signum == SIGUSR1)
	{
		while (1)
		{
			ssize_t unused = read(lopt.cd_pipe[0], &card, sizeof(int));
			if (unused < 0)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return;
				// error occurred
				perror("read");
				return;
			}
			else if (unused == 0)
			{
				// EOF
				perror("EOF encountered read(opt.cd_pipe[0])");
				return;
			}
			else if (unused != (ssize_t) sizeof(int))
				return;

			unused = read(lopt.ch_pipe[0], &value, sizeof(int));
			if (unused < 0)
			{
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return;
				perror("read");
				return;
			}
			else if (unused != (ssize_t) sizeof(int))
				return;

			process_hopper_event(card, value);
		}
	}

	if (signum == SIGUSR2)
		IGNORE_LTZ(read(lopt.gc_pipe[0], &lopt.gps_loc, sizeof(lopt.gps_loc)));

	if (signum == SIGINT || signum == SIGTERM)
	{
		if (getpid() != main_pid)
			_exit(0);
		lopt.do_exit = 1;
		if (!use_ncurses_tui)
		{
			show_cursor();
			reset_term();
		}
		fprintf(stdout, "Quitting...\n");
	}

	if (signum == SIGSEGV)
	{
		fprintf(stderr,
				"Caught signal 11 (SIGSEGV). Please"
				" contact the author!\n\n");
		if (!use_ncurses_tui) show_cursor();
		fflush(stdout);
		exit(1);
	}

	if (signum == SIGALRM)
	{
		fprintf(stdout,
				"Caught signal 14 (SIGALRM). Please"
				" contact the author!\n\n");
		if (!use_ncurses_tui) show_cursor();
		_exit(1);
	}

	if (signum == SIGCHLD) wait(NULL);

	if (signum == SIGWINCH)
	{
		if (use_ncurses_tui)
			tui_resize_pending = 1;
		else
		{
			erase_display(0);
			fflush(stdout);
		}
	}
}

static int send_probe_request(struct wif * wi)
{
	REQUIRE(wi != NULL);

	int len;
	uint8_t p[4096], r_smac[6];

	memcpy(p, PROBE_REQ, 24);

	len = 24;

	p[24] = 0x00; // ESSID Tag Number
	p[25] = 0x00; // ESSID Tag Length

	len += 2;

	memcpy(p + len, RATES, 16);

	len += 16;

	r_smac[0] = 0x00;
	r_smac[1] = rand_u8();
	r_smac[2] = rand_u8();
	r_smac[3] = rand_u8();
	r_smac[4] = rand_u8();
	r_smac[5] = rand_u8();

	memcpy(p + 10, r_smac, 6);

	if (wi_write(wi, NULL, LINKTYPE_IEEE802_11, p, len, NULL) == -1)
	{
		switch (errno)
		{
			case EAGAIN:
			case ENOBUFS:
				usleep(10000);
				return (0); /* XXX not sure I like this... -sorbo */
			default:
				break;
		}

		perror("wi_write()");
		return (-1);
	}

	return (0);
}

static int send_probe_requests(struct wif * wi[], int cards)
{
	REQUIRE(wi != NULL);
	REQUIRE(cards > 0);

	int i = 0;
	for (i = 0; i < cards; i++)
	{
		send_probe_request(wi[i]);
	}

	return (0);
}

static int getchancount(int valid)
{
	int i = 0, chan_count = 0;

	while (lopt.channels[i])
	{
		i++;
		if (lopt.channels[i] != -1) chan_count++;
	}

	if (valid) return (chan_count);
	return (i);
}

static int getfreqcount(int valid)
{
	int i = 0, freq_count = 0;

	while (lopt.own_frequencies[i])
	{
		i++;
		if (lopt.own_frequencies[i] != -1) freq_count++;
	}

	if (valid) return (freq_count);
	return (i);
}

static void report_hopper_update(pid_t parent, int card, int value)
{
	IGNORE_LTZ(write(lopt.cd_pipe[1], &card, sizeof(int)));
	IGNORE_LTZ(write(lopt.ch_pipe[1], &value, sizeof(int)));
	kill(parent, SIGUSR1);
	usleep(1000);
}

static void set_hopper_pipe_nonblocking(void)
{
	int flags;

	flags = fcntl(lopt.cd_pipe[0], F_GETFL, 0);
	if (flags >= 0)
		IGNORE_LTZ(fcntl(lopt.cd_pipe[0], F_SETFL, flags | O_NONBLOCK));

	flags = fcntl(lopt.ch_pipe[0], F_GETFL, 0);
	if (flags >= 0)
		IGNORE_LTZ(fcntl(lopt.ch_pipe[0], F_SETFL, flags | O_NONBLOCK));
}

static void report_hopper_scan_wrap(pid_t parent)
{
	report_hopper_update(parent, -1, 0);
}

static void
channel_hopper(struct wif * wi[], int if_num, int chan_count, pid_t parent)
{
	int ch, ch_idx = 0, card = 0, chi = 0, cai = 0, j = 0, k = 0, first = 1,
			again;
	int dropped = 0;

	while (0 == kill(parent, 0))
	{
		for (j = 0; j < if_num; j++)
		{
			again = 1;

			ch_idx = chi % chan_count;
			if (!first && ch_idx == 0)
				report_hopper_scan_wrap(parent);

			card = cai % if_num;

			++chi;
			++cai;

			if (lopt.chswitch == 2 && !first)
			{
				j = if_num - 1;
				card = if_num - 1;

				if (getchancount(1) > if_num)
				{
					while (again)
					{
						again = 0;
						for (k = 0; k < (if_num - 1); k++)
						{
							if (lopt.channels[ch_idx] == lopt.channel[k])
							{
								again = 1;
								ch_idx = chi % chan_count;
								chi++;
							}
						}
					}
				}
			}

			if (lopt.channels[ch_idx] == -1)
			{
				j--;
				cai--;
				dropped++;
				if (dropped >= chan_count)
				{
					ch = wi_get_channel(wi[card]);
					lopt.channel[card] = ch;
					report_hopper_update(parent, card, ch);
				}
				continue;
			}

			dropped = 0;

			ch = lopt.channels[ch_idx];

#ifdef CONFIG_LIBNL
			if (wi_set_ht_channel(wi[card], ch, lopt.htval) == 0)
#else
			if (wi_set_channel(wi[card], ch) == 0)
#endif
			{
				lopt.channel[card] = ch;
				if (lopt.active_scan_sim > 0) send_probe_request(wi[card]);
				report_hopper_update(parent, card, ch);
			}
			else
			{
				report_hopper_update(parent, card, -ch);
				lopt.channels[ch_idx] = -1; /* remove invalid channel */
				j--;
				cai--;
				continue;
			}
		}

		if (lopt.chswitch == 0)
		{
			chi = chi - (if_num - 1);
		}

		if (first)
		{
			first = 0;
		}

		usleep((useconds_t)(lopt.hopfreq * 1000));
	}

	exit(0);
}

static void
frequency_hopper(struct wif * wi[], int if_num, int chan_count, pid_t parent)
{
	int ch, ch_idx = 0, card = 0, chi = 0, cai = 0, j = 0, k = 0, first = 1,
			again;
	int dropped = 0;

	while (0 == kill(parent, 0))
	{
		for (j = 0; j < if_num; j++)
		{
			again = 1;

			ch_idx = chi % chan_count;
			if (!first && ch_idx == 0)
				report_hopper_scan_wrap(parent);

			card = cai % if_num;

			++chi;
			++cai;

			if (lopt.chswitch == 2 && !first)
			{
				j = if_num - 1;
				card = if_num - 1;

				if (getfreqcount(1) > if_num)
				{
					while (again)
					{
						again = 0;
						for (k = 0; k < (if_num - 1); k++)
						{
							if (lopt.own_frequencies[ch_idx]
								== lopt.frequency[k])
							{
								again = 1;
								ch_idx = chi % chan_count;
								chi++;
							}
						}
					}
				}
			}

			if (lopt.own_frequencies[ch_idx] == -1)
			{
				j--;
				cai--;
				dropped++;
				if (dropped >= chan_count)
				{
					ch = wi_get_freq(wi[card]);
					lopt.frequency[card] = ch;
					report_hopper_update(parent, card, ch);
				}
				continue;
			}

			dropped = 0;

			ch = lopt.own_frequencies[ch_idx];

			if ((lopt.band_mode == BAND_MODE_AX
				 ? wi_set_freq_ax(wi[card], ch, lopt.ax_bw, lopt.c_seg0, lopt.c_seg1)
				 : wi_set_freq(wi[card], ch)) == 0)
			{
				int effective = wi_get_freq(wi[card]);

				if (effective != ch)
				{
					usleep(10000);
					effective = wi_get_freq(wi[card]);
				}
				if (lopt.band_mode == BAND_MODE_AX && effective <= 0)
					effective = ch;

				if (effective == ch)
				{
					lopt.frequency[card] = ch;
					report_hopper_update(parent, card, ch);
				}
				else
				{
					report_hopper_update(parent, card, -ch);
					lopt.own_frequencies[ch_idx] = -1; /* remove invalid frequency */
					j--;
					cai--;
					continue;
				}
			}
			else
			{
				report_hopper_update(parent, card, -ch);
				lopt.own_frequencies[ch_idx] = -1; /* remove invalid frequency */
				j--;
				cai--;
				continue;
			}
		}

		if (lopt.chswitch == 0)
		{
			chi = chi - (if_num - 1);
		}

		if (first)
		{
			first = 0;
		}

		usleep((useconds_t)(lopt.hopfreq * 1000));
	}

	exit(0);
}

// takes in an array of channels, checks against the band a freq set, creates string of freqs 
static void channels_to_freq_string_a(const int *channels, char *freq_string) {

    int len = strlen(freq_string);
	int available = MAX_FREQS * MAX_FREQ_STR_LEN - len - 1; // Available space, -1 for null terminator
    for (int i = 0; channels[i] != 0 && available > 0; ++i) {
        for (int j = 0; channel_frequency_map_a[j] != -1; j += 2) {
            if (channels[i] == channel_frequency_map_a[j]) {
                // Calculate space needed for this frequency (including comma if not the first entry)
                int needed_space = snprintf(NULL, 0, "%s%d", len > 0 ? "," : "", channel_frequency_map_a[j + 1]);

                if (needed_space <= available) {
                    // Append frequency to string if enough space is available
                    int written = snprintf(freq_string + len, needed_space + 1, "%s%d",
                                           len > 0 ? "," : "", channel_frequency_map_a[j + 1]);
                    len += written;
                    available -= written;
                } else {
                    // Not enough space to append the next frequency
                    return;
                }
                break; // Found and processed the channel, move to the next
            }
        }
    }
}

//takes in an array of channels, checks against the band bg freq set, creates string of freqs
static void channels_to_freq_string_bg(const int *channels, char *freq_string) {

    int len = strlen(freq_string);
	int available = MAX_FREQS * MAX_FREQ_STR_LEN - len - 1; // Available space, -1 for null terminator
    for (int i = 0; channels[i] != 0; ++i) {
        for (int j = 0; channel_frequency_map_bg[j] != -1; j += 2) {
            if (channels[i] == channel_frequency_map_bg[j]) {
                // Calculate space needed for this frequency (including comma if not the first entry)
                int needed_space = snprintf(NULL, 0, "%s%d", len > 0 ? "," : "", channel_frequency_map_bg[j + 1]);

                if (needed_space <= available) {
                    // Append frequency to string if enough space is available
                    int written = snprintf(freq_string + len, needed_space + 1, "%s%d",
                                           len > 0 ? "," : "", channel_frequency_map_bg[j + 1]);
                    len += written;
                    available -= written;
                } else {
                    // Not enough space to append the next frequency
                    return;
                }
                break; // Found and processed the channel, move to the next
            }
        }
    }
}

// Function to map 6 GHz channel number to frequency (in MHz)
static int channel_to_frequency_ax(int channel) {
	// Fixed first and last channel numbers
    int first_channel = channel_frequency_map_ax[0];
	// -4 to get the last channel number before the end marker
    int last_channel = channel_frequency_map_ax[sizeof(channel_frequency_map_ax) / sizeof(channel_frequency_map_ax[0]) - 4];

    // Check if the channel number is within the valid range
    if (channel < first_channel || channel > last_channel) {
        return -1;
    }

    // Iterate over the lookup table to find the frequency
    for (int i = 0; channel_frequency_map_ax[i] != -1; i += 2) {
        if (channel_frequency_map_ax[i] == channel) {
            return channel_frequency_map_ax[i + 1];
        }
    }
    return -1; // Channel not found, return invalid
}

static int channel_to_frequency(int channel)
{
	int i;

	for (i = 0; channel_frequency_map_bg[i] != -1; i += 2)
	{
		if (channel_frequency_map_bg[i] == channel)
			return (channel_frequency_map_bg[i + 1]);
	}

	for (i = 0; channel_frequency_map_a[i] != -1; i += 2)
	{
		if (channel_frequency_map_a[i] == channel)
			return (channel_frequency_map_a[i + 1]);
	}

	return (channel_to_frequency_ax(channel));
}

static int frequency_to_channel(int frequency)
{
	int channel = getChannelFromFrequency(frequency);

	if (channel > 0)
		return (channel);

	return (frequency);
}

static int band_from_frequency_or_channel(int frequency, int channel)
{
	if (frequency >= 2400 && frequency < 2500)
		return (24);
	if (frequency >= 4900 && frequency < 5925)
		return (5);
	if (frequency >= 5925 && frequency <= 7125)
		return (6);

	if (lopt.band_mode == BAND_MODE_AX)
		return (6);
	if (lopt.band_mode == BAND_MODE_A)
		return (5);
	if (lopt.band_mode == BAND_MODE_BG)
		return (24);

	if (channel > 14)
		return (5);
	if (channel > 0)
		return (24);
	return (0);
}

static int band_from_rx_info(const struct rx_info * ri, int channel)
{
	if (ri == NULL)
		return (band_from_frequency_or_channel(0, channel));
	return (band_from_frequency_or_channel((int) ri->ri_freq, channel));
}

static int channel_is_valid_for_band(int channel)
{
	size_t i;

	if (channel <= 0) return (0);

	switch (lopt.band_mode)
	{
		case BAND_MODE_BG:
			for (i = 0; bg_chans[i] != 0; i++)
				if (bg_chans[i] == channel) return (1);
			return (0);
		case BAND_MODE_A:
			for (i = 0; a_chans[i] != 0; i++)
				if (a_chans[i] == channel) return (1);
			return (0);
		case BAND_MODE_AX:
			for (i = 0; ax_chans[i] != 0; i++)
				if (ax_chans[i] == channel) return (1);
			return (0);
		default:
			return (channel_to_frequency(channel) > 0);
	}
}

static int park_on_channel(int channel)
{
	struct wif * wi[MAX_CARDS];
	int i;
	int freq;

	if (g_wi == NULL || g_wi[0] == NULL)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ no wireless interface available");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	if (!channel_is_valid_for_band(channel))
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ channel %d is not valid for %s",
				 channel,
				 band_mode_label(lopt.band_mode));
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	for (i = 0; i < MAX_CARDS; i++)
		wi[i] = NULL;
	for (i = 0; i < lopt.num_cards; i++)
		wi[i] = g_wi[i];

	stop_hopper();

	if (lopt.freqoption)
	{
		freq = channel_to_frequency(channel);
		if (freq <= 0)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ unable to map channel %d to a frequency",
					 channel);
			append_tui_message_history_now(lopt.message);
			return (0);
		}

		for (i = 0; i < lopt.num_cards; i++)
		{
#ifdef CONFIG_LIBNL
			if (wi_set_freq_ax(wi[i], freq, lopt.ax_bw, lopt.c_seg0, lopt.c_seg1)
				!= 0)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to tune to channel %d",
						 channel);
				append_tui_message_history_now(lopt.message);
				return (0);
			}
#else
			if (wi_set_freq(wi[i], freq) != 0)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to tune to channel %d",
						 channel);
				append_tui_message_history_now(lopt.message);
				return (0);
			}
#endif
			lopt.frequency[i] = freq;
		}
		lopt.singlefreq = 1;
		lopt.singlechan = 0;
	}
	else
	{
		for (i = 0; i < lopt.num_cards; i++)
		{
#ifdef CONFIG_LIBNL
			if (wi_set_ht_channel(wi[i], channel, lopt.htval) != 0)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to tune to channel %d",
						 channel);
				append_tui_message_history_now(lopt.message);
				return (0);
			}
#else
			if (wi_set_channel(wi[i], channel) != 0)
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ failed to tune to channel %d",
						 channel);
				append_tui_message_history_now(lopt.message);
				return (0);
			}
#endif
			lopt.channel[i] = channel;
		}
		lopt.singlechan = 1;
		lopt.singlefreq = 0;
	}

	return (1);
}

static void begin_channel_entry(void)
{
	channel_entry_active = 1;
	channel_entry_len = 0;
	channel_entry_buf[0] = '\0';
	set_channel_entry_prompt();
	if (use_ncurses_tui)
		render_output_view(0);
}

static void cancel_channel_entry(const char * message)
{
	channel_entry_active = 0;
	channel_entry_len = 0;
	channel_entry_buf[0] = '\0';
	channel_entry_prompt[0] = '\0';
	if (message != NULL)
		snprintf(lopt.message, sizeof(lopt.message), "%s", message);
}

static int apply_channel_entry(void)
{
	int channel;
	int frequency;

	channel = atoi(channel_entry_buf);
	channel_entry_active = 0;
	channel_entry_len = 0;
	channel_entry_buf[0] = '\0';
	channel_entry_prompt[0] = '\0';

	if (channel <= 0)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ invalid channel entry");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	if (!park_on_channel(channel))
		return (0);

	frequency = channel_to_frequency(channel);
	snprintf(lopt.message,
			 sizeof(lopt.message),
			 "][ channel %d selected (%d MHz)",
			 channel,
			 frequency);
	append_tui_message_history_now(lopt.message);
	return (1);
}

static int lock_selected_ap_channel(void)
{
	struct AP_info * ap_cur;

	ap_cur = lopt.p_selected_ap;
	if (ap_cur == NULL || ap_cur->channel <= 0)
		return (0);

	if (!park_on_channel(ap_cur->channel))
		return (0);

	if (lopt.freqoption)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ locked to AP channel %d (%d MHz)",
				 ap_cur->channel,
				 channel_to_frequency(ap_cur->channel));
	}
	else
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ locked to AP channel %d",
				 ap_cur->channel);
	}
	append_tui_message_history_now(lopt.message);
	return (1);
}

static int write_wpa_snapshot(void)
{
	char filename[128];
	struct tm * lt;
	time_t now;
	size_t records = 0;

	now = time(NULL);
	lt = localtime(&now);
	if (lt == NULL)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ failed to build handshake snapshot name");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	snprintf(filename,
			 sizeof(filename),
			 "handshakes-%02d%02d-%02d%02d%02d.ivs",
			 lt->tm_mon + 1,
			 lt->tm_mday,
			 lt->tm_hour,
			 lt->tm_min,
			 lt->tm_sec);

	if (dump_write_wpa_snapshot(filename, lopt.st_1st, &records) != 0)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ failed to write WPA snapshot");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	if (records == 0)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ no WPA handshakes buffered");
		append_tui_message_history_now(lopt.message);
		return (0);
	}

	snprintf(lopt.message,
			 sizeof(lopt.message),
			 "][ wrote %zu WPA record%s to %s",
			 records,
			 records == 1 ? "" : "s",
			 filename);
	append_tui_message_history_now(lopt.message);
	return (1);
}

static void stop_hopper(void)
{
	int status;

	if (hopper_pid <= 0) return;

	kill(hopper_pid, SIGTERM);
	while (waitpid(hopper_pid, &status, 0) < 0)
	{
		if (errno != EINTR)
			break;
	}
	hopper_pid = -1;
}

static int resume_hopper(void)
{
	struct wif * wi[MAX_CARDS];
	char ifnam[64];
	int chan_count = 0;
	int freq_count = 0;
	int i;
	pid_t child_pid;

	if (g_wi == NULL || g_wi[0] == NULL)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ no wireless interface available");
		return (0);
	}

	if (hopper_pid > 0)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ channel hopping already running");
		append_tui_message_history(lopt.message, time(NULL));
		return (1);
	}

	for (i = 0; i < MAX_CARDS; i++)
		wi[i] = NULL;
	for (i = 0; i < lopt.num_cards; i++)
		wi[i] = g_wi[i];

	if (lopt.freqoption)
	{
		freq_count = getfreqcount(0);
		if (freq_count <= 0)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ no frequencies available for hopping");
			append_tui_message_history(lopt.message, time(NULL));
			return (0);
		}
	}
	else
	{
		chan_count = getchancount(0);
		if (chan_count <= 0)
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ no channels available for hopping");
			append_tui_message_history(lopt.message, time(NULL));
			return (0);
		}
	}

	if (!hopper_pipe_ready)
	{
		struct sigaction action;

		IGNORE_NZ(pipe(lopt.ch_pipe));
		IGNORE_NZ(pipe(lopt.cd_pipe));
		set_hopper_pipe_nonblocking();

		action.sa_flags = 0;
		action.sa_handler = &sighandler;
		sigemptyset(&action.sa_mask);

		if (sigaction(SIGUSR1, &action, NULL) == -1)
			perror("sigaction(SIGUSR1)");
		hopper_pipe_ready = 1;
	}

	reset_hopper_reject_state();
	hopper_reject_total = lopt.freqoption ? freq_count : chan_count;
	child_pid = fork();
	if (child_pid == 0)
	{
		/* reopen cards.  This way parent & child don't share
		 * resources for accessing the card (e.g. file descriptors)
		 * which may cause problems.  -sorbo
		 */
		for (i = 0; i < lopt.num_cards; i++)
		{
			strlcpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam));

			wi_close(wi[i]);
			wi[i] = wi_open(ifnam);
			if (!wi[i])
			{
				printf("Can't reopen %s\n", ifnam);
				exit(EXIT_FAILURE);
			}
		}

		/* Drop privileges */
		if (setuid(getuid()) == -1)
		{
			perror("setuid");
		}

		if (lopt.freqoption)
			frequency_hopper(wi, lopt.num_cards, freq_count, main_pid);
		else
			channel_hopper(wi, lopt.num_cards, chan_count, main_pid);
		exit(EXIT_FAILURE);
	}
	else if (child_pid < 0)
	{
		perror("fork");
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ failed to resume channel hopping");
		append_tui_message_history(lopt.message, time(NULL));
		return (0);
	}

	hopper_pid = child_pid;
	lopt.singlechan = 0;
	lopt.singlefreq = 0;
	snprintf(lopt.message, sizeof(lopt.message), "][ channel hopping resumed");
	append_tui_message_history(lopt.message, time(NULL));
	return (1);
}

static const char * band_mode_label(int band_mode)
{
	switch (band_mode)
	{
		case BAND_MODE_BG:
			return ("2.4 GHz");
		case BAND_MODE_A:
			return ("5 GHz");
		case BAND_MODE_AX:
			return ("6 GHz");
		default:
			return ("2.4 GHz");
	}
}

static int infer_band_mode(void)
{
	if (lopt.scan_11ax)
		return (BAND_MODE_AX);

	if (lopt.channels == (int *) a_chans)
		return (BAND_MODE_A);

	if (lopt.channels == (int *) bg_chans)
		return (BAND_MODE_BG);

	if (lopt.channel[0] > 14)
		return (BAND_MODE_A);

	return (BAND_MODE_BG);
}

static int band_support_mask_for_interface(const char * ifname)
{
	FILE * fp;
	char line[256];
	char phy_name[32];
	char cmd[128];
	int mask = 0;

	if (ifname == NULL || *ifname == '\0') return (-1);

	snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null", ifname);
	fp = popen(cmd, "r");
	if (fp == NULL) return (-1);

	phy_name[0] = '\0';
	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char * p = line;
		int phy_index;

		while (isspace((unsigned char) *p))
			p++;
		if (sscanf(p, "wiphy %d", &phy_index) == 1)
		{
			snprintf(phy_name, sizeof(phy_name), "phy%d", phy_index);
			break;
		}
	}
	pclose(fp);

	if (phy_name[0] == '\0') return (-1);

	snprintf(cmd, sizeof(cmd), "iw phy %s info 2>/dev/null", phy_name);
	fp = popen(cmd, "r");
	if (fp == NULL) return (-1);

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		char * p = line;
		int freq;

		while (isspace((unsigned char) *p))
			p++;
		if (*p != '*') continue;
		p++;
		while (isspace((unsigned char) *p))
			p++;
		if (sscanf(p, "%d", &freq) != 1) continue;

		if (freq >= 2400 && freq < 2500)
			mask |= (1 << BAND_MODE_BG);
		else if (freq >= 4900 && freq < 5925)
			mask |= (1 << BAND_MODE_A);
		else if (freq >= 5925 && freq <= 7125)
			mask |= (1 << BAND_MODE_AX);
	}

	pclose(fp);
	return (mask);
}

static int band_support_mask_for_cards(struct wif * wi[], int num_cards)
{
	int mask = 0;
	int have_mask = 0;
	int i;

	if (wi == NULL || num_cards <= 0) return (-1);

	for (i = 0; i < num_cards; i++)
	{
		const char * ifname;
		int card_mask;

		if (wi[i] == NULL) continue;
		ifname = wi_get_ifname(wi[i]);
		card_mask = band_support_mask_for_interface(ifname);
		if (card_mask < 0)
			continue;
		if (!have_mask)
		{
			mask = card_mask;
			have_mask = 1;
		}
		else
		{
			mask &= card_mask;
		}
	}

	return (have_mask ? mask : -1);
}

static int band_mode_is_supported(int band_mode)
{
	int mask = supported_band_mode_mask();

	if (band_mode < BAND_MODE_BG || band_mode > BAND_MODE_AX)
		return (0);
	return ((mask & (1 << band_mode)) != 0);
}

static int supported_band_mode_mask(void)
{
	if (lopt.band_support_mask < 0)
		return ((1 << BAND_MODE_BG) | (1 << BAND_MODE_A) | (1 << BAND_MODE_AX));
	return (lopt.band_support_mask);
}

static int next_supported_band_mode(int current_band_mode, int direction)
{
	const int bands[] = {BAND_MODE_BG, BAND_MODE_A, BAND_MODE_AX};
	int mask = supported_band_mode_mask();
	int idx = 0;
	int step = 1;
	int i;

	if (direction < 0)
		step = -1;
	for (i = 0; i < (int) ArrayCount(bands); i++)
	{
		if (bands[i] == current_band_mode)
		{
			idx = i;
			break;
		}
	}

	for (i = 1; i <= (int) ArrayCount(bands); i++)
	{
		int candidate = bands[(idx + (step * i) + (int) ArrayCount(bands)) % (int) ArrayCount(bands)];

		if (mask & (1 << candidate))
			return (candidate);
	}

	return (current_band_mode);
}

static int build_ax_frequency_list(int ** freqs_out)
{
	size_t count = 0;
	size_t i;
	int * freqs;
	int allowed_freqs[AIRODUMP_TUI_MAX_CHANNEL_STATUS];
	int use_allowed_freqs = 0;

	REQUIRE(freqs_out != NULL);

	count = get_allowed_ax_frequencies(allowed_freqs, ArrayCount(allowed_freqs));
	if (count == 0)
		while (ax_chans[count] != 0)
			count++;
	else
		use_allowed_freqs = 1;
	freqs = (int *) malloc(sizeof(int) * (count + 1));
	if (freqs == NULL) return (0);

	if (use_allowed_freqs)
	{
		for (i = 0; i < count; i++)
			freqs[i] = allowed_freqs[i];
	}
	else
	{
		for (i = 0; i < count; i++)
			freqs[i] = channel_to_frequency_ax(ax_chans[i]);
	}
	freqs[count] = 0;
	*freqs_out = freqs;
	return (1);
}

static int switch_band(int direction)
{
	int old_band_mode = lopt.band_mode;
	int * old_own_frequencies = lopt.own_frequencies;
	int next_band_mode;
	int * new_freqs = NULL;
	int supported_mask;
	int success;

	if (direction == 0) direction = 1;
	supported_mask = supported_band_mode_mask();
	if (supported_mask == 0)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ no supported bands available");
		append_tui_message_history(lopt.message, time(NULL));
		return (0);
	}
	next_band_mode = next_supported_band_mode(lopt.band_mode, direction);
	if (next_band_mode == lopt.band_mode
		&& !band_mode_is_supported(lopt.band_mode))
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ no supported bands available");
		append_tui_message_history(lopt.message, time(NULL));
		return (0);
	}
	if (next_band_mode == lopt.band_mode)
	{
		snprintf(lopt.message,
				 sizeof(lopt.message),
				 "][ %s is the only supported band",
				 band_mode_label(lopt.band_mode));
		append_tui_message_history(lopt.message, time(NULL));
		return (0);
	}

	if (next_band_mode == BAND_MODE_AX)
	{
		if (!build_ax_frequency_list(&new_freqs))
		{
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ unable to build 6 GHz band list");
			append_tui_message_history(lopt.message, time(NULL));
			return (0);
		}
	}

	stop_hopper();

	if (next_band_mode == BAND_MODE_AX)
	{
		lopt.channels = (int *) ax_chans;
		lopt.freqoption = 1;
		lopt.chanoption = 0;
		lopt.own_frequencies = new_freqs;
	}
	else if (next_band_mode == BAND_MODE_A)
	{
		lopt.channels = (int *) a_chans;
		lopt.freqoption = 0;
		lopt.chanoption = 1;
	}
	else
	{
		lopt.channels = (int *) bg_chans;
		lopt.freqoption = 0;
		lopt.chanoption = 1;
	}

	lopt.singlechan = 0;
	lopt.singlefreq = 0;
	lopt.band_mode = next_band_mode;

	success = resume_hopper();
	if (!success)
	{
		if (next_band_mode == BAND_MODE_AX && new_freqs != NULL)
		{
			free(new_freqs);
		}
		lopt.band_mode = old_band_mode;
		lopt.own_frequencies = old_own_frequencies;
		return (0);
	}

	if (next_band_mode != BAND_MODE_AX && old_own_frequencies != NULL)
	{
		free(old_own_frequencies);
		lopt.own_frequencies = NULL;
	}
	else if (next_band_mode == BAND_MODE_AX && old_own_frequencies != NULL
			 && old_own_frequencies != new_freqs)
	{
		free(old_own_frequencies);
	}

	snprintf(lopt.message,
			 sizeof(lopt.message),
			 "][ band switched to %s",
			 band_mode_label(lopt.band_mode));
	append_tui_message_history(lopt.message, time(NULL));
	return (1);
}

// Function to convert channel array to frequency string
static void channels_to_freq_string_ax(const int *channels, char *freq_string) {
    //char buffer[MAX_FREQ_STR_LEN];
	int len = strlen(freq_string);
	int available = MAX_FREQS * MAX_FREQ_STR_LEN - len - 1; // Available space, -1 for null terminator

    for (int i = 0; channels[i] != 0; ++i) {
		
        int freq = channel_to_frequency_ax(channels[i]);
        if (freq > 0) {
            // Calculate space needed for this frequency (including comma if not the first entry)
			int needed_space = snprintf(NULL, 0, "%s%d", len > 0 ? "," : "", freq);

			if (needed_space <= available) {
				// Append frequency to string if enough space is available
				int written = snprintf(freq_string + len, needed_space + 1, "%s%d",
										len > 0 ? "," : "", freq);
				len += written;
				available -= written;
			} else {
				// Not enough space to append the next frequency
				return;
			}
        }
    }
}

static inline int invalid_channel(int chan, int is_6GHz)
{
	int i = 0;
	const int *channel_array = is_6GHz ? ax_chans : abg_chans;
	do
	{
		if (chan == channel_array[i] && chan != 0) return (0);
	} while (channel_array[++i]);
	return (1);
}

static inline int invalid_frequency(int freq)
{
	int i = 0;

	do
	{
		if (freq == frequencies[i] && freq != 0) return (0);
	} while (frequencies[++i]);
	return (1);
}

/* parse a string, for example "1,2,3-7,11" */

static int getchannels(const char * optarg)
{
#define GETCHANNELS_CHAN_MAX 128u
	size_t i = 0, chan_cur = 0, chan_first = 0, chan_last = 0,
		   chan_max = GETCHANNELS_CHAN_MAX, chan_remain = 0;
	char *optchan = NULL, *optc;
	char * token = NULL;
	int tmp_channels[GETCHANNELS_CHAN_MAX + 1] = {0};
	
	// got a NULL pointer?
	if (optarg == NULL) return (-1);

	chan_remain = chan_max;

	// create a writable string
	const size_t optchan_len = strlen(optarg) + 1;
	optc = optchan = (char *) malloc(optchan_len);
	ALLEGE(optc != NULL);
	ALLEGE(optchan != NULL);
	strlcpy(optchan, optarg, optchan_len);

	// split string in tokens, separated by ','
	while ((token = strsep(&optchan, ",")) != NULL)
	{
		const size_t token_len = strlen(token);

		// range defined?
		if (strchr(token, '-') != NULL)
		{
			// only 1 '-' ?
			if (strchr(token, '-') == strrchr(token, '-'))
			{
				// are there any illegal characters?
				for (i = 0; i < token_len; i++)
				{
					if (((token[i] < '0') || (token[i] > '9'))
						&& (token[i] != '-'))
					{
						free(optc);
						return (-1);
					}
				}

				if (sscanf(token, "%zu-%zu", &chan_first, &chan_last) != EOF)
				{
					if (chan_first > chan_last)
					{
						free(optc);
						return (-1);
					}
					for (i = chan_first; i <= chan_last; i++)
					{
						if ((!invalid_channel(i, lopt.scan_11ax)) && (chan_remain > 0))
						{
							tmp_channels[chan_max - chan_remain] = i;
							chan_remain--;
						}
					}
				}
				else
				{
					free(optc);
					return (-1);
				}
			}
			else
			{
				free(optc);
				return (-1);
			}
		}
		else
		{
			// are there any illegal characters?
			for (i = 0; i < token_len; i++)
			{
				if ((token[i] < '0') || (token[i] > '9'))
				{
					free(optc);
					return (-1);
				}
			}

			if (sscanf(token, "%zu", &chan_cur) != EOF)
			{
				if ((!invalid_channel(chan_cur, lopt.scan_11ax)) && (chan_remain > 0))
				{
					tmp_channels[chan_max - chan_remain] = chan_cur;
					chan_remain--;
				}
			}
			else
			{
				free(optc);
				return (-1);
			}
		}
	}

	lopt.own_channels
		= (int *) malloc(sizeof(int) * (chan_max - chan_remain + 1));
	ALLEGE(lopt.own_channels != NULL);

	if (chan_max > 0 && chan_max >= chan_remain) //-V560
	{
		for (i = 0; i < (chan_max - chan_remain); i++) //-V658
		{
			lopt.own_channels[i] = tmp_channels[i];
		}
	}

	lopt.own_channels[i] = 0;

	free(optc);

	if (i == 1) return (lopt.own_channels[0]);
	if (i == 0) return (-1);
	return (0);
}

/* parse a string, for example "1,2,3-7,11" */

static int getfrequencies(const char * optarg)
{
	size_t i = 0, freq_cur = 0, freq_first = 0, freq_last = 0, freq_max = 10000,
		   freq_remain = 0;
	char *optfreq = NULL, *optc;
	char * token = NULL;
	int * tmp_frequencies;

	// got a NULL pointer?
	if (optarg == NULL) return -1;
	
	freq_remain = freq_max;

	// create a writable string
	const size_t optfreq_len = strlen(optarg) + 1;
	optc = optfreq = (char *) malloc(optfreq_len);
	ALLEGE(optc != NULL);
	ALLEGE(optfreq != NULL);
	strlcpy(optfreq, optarg, optfreq_len);

	tmp_frequencies = (int *) malloc(sizeof(int) * (freq_max + 1));
	ALLEGE(tmp_frequencies != NULL);

	// split string in tokens, separated by ','
	while ((token = strsep(&optfreq, ",")) != NULL)
	{
		const size_t token_len = strlen(token);

		// range defined?
		if (strchr(token, '-') != NULL)
		{
			// only 1 '-' ?
			if (strchr(token, '-') == strrchr(token, '-'))
			{
				// are there any illegal characters?
				for (i = 0; i < token_len; i++)
				{
					if ((token[i] < '0' || token[i] > '9') && (token[i] != '-'))
					{
						free(tmp_frequencies);
						free(optc);
						return (-1);
					}
				}

				if (sscanf(token, "%zu-%zu", &freq_first, &freq_last) != EOF)
				{
					if (freq_first > freq_last)
					{
						free(tmp_frequencies);
						free(optc);
						return (-1);
					}
					for (i = freq_first; i <= freq_last; i++)
					{
						if ((!invalid_frequency(i)) && (freq_remain > 0))
						{
							tmp_frequencies[freq_max - freq_remain] = i;
							freq_remain--;
						}
					}
				}
				else
				{
					free(tmp_frequencies);
					free(optc);
					return (-1);
				}
			}
			else
			{
				free(tmp_frequencies);
				free(optc);
				return (-1);
			}
		}
		else
		{
			// are there any illegal characters?
			for (i = 0; i < token_len; i++)
			{
				if ((token[i] < '0') || (token[i] > '9'))
				{
					free(tmp_frequencies);
					free(optc);
					return (-1);
				}
			}

			if (sscanf(token, "%zu", &freq_cur) != EOF)
			{
				if ((!invalid_frequency(freq_cur)) && (freq_remain > 0))
				{
					tmp_frequencies[freq_max - freq_remain] = freq_cur;
					freq_remain--;
				}

				/* special case "-C 0" means: scan all available frequencies */
				if (freq_cur == 0)
				{
					freq_first = 1;
					freq_last = 9999;
					for (i = freq_first; i <= freq_last; i++)
					{
						if ((!invalid_frequency(i)) && (freq_remain > 0))
						{
							tmp_frequencies[freq_max - freq_remain] = i;
							freq_remain--;
						}
					}
				}
			}
			else
			{
				free(tmp_frequencies);
				free(optc);
				return (-1);
			}
		}
	}

	lopt.own_frequencies
		= (int *) malloc(sizeof(int) * (freq_max - freq_remain + 1));
	ALLEGE(lopt.own_frequencies != NULL);

	if (freq_max > 0 && freq_max >= freq_remain) //-V560
	{
		for (i = 0; i < (freq_max - freq_remain); i++) //-V658
		{
			lopt.own_frequencies[i] = tmp_frequencies[i];
		}
	}

	lopt.own_frequencies[i] = 0;

	free(tmp_frequencies);
	free(optc);
	if (i == 1) return (lopt.own_frequencies[0]); // exactly 1 frequency given
	if (i == 0) return (-1); // error occurred
	return (0); // frequency hopping
}

static int setup_card(char * iface, struct wif ** wis)
{
	REQUIRE(iface != NULL);
	REQUIRE(wis != NULL);

	struct wif * wi;

	wi = wi_open(iface);
	if (!wi) return (-1);
	*wis = wi;

	return (0);
}

static int init_cards(const char * cardstr, char * iface[], struct wif ** wi)
{
	char * buffer;
	char * buf;
	int if_count = 0;
	int i = 0, again = 0;

	// Check card string is valid
	if (cardstr == NULL || cardstr[0] == 0)
	{
		return (-1);
	}

	buf = buffer = strdup(cardstr);
	if (buf == NULL)
	{
		return (-1);
	}

	while ((if_count < MAX_CARDS)
		   && ((iface[if_count] = strsep(&buffer, ",")) != NULL))
	{
		again = 0;
		for (i = 0; i < if_count; i++)
		{
			if (strcmp(iface[i], iface[if_count]) == 0) again = 1;
		}
		if (again) continue;
		if (setup_card(iface[if_count], &(wi[if_count])) != 0)
		{
			free(buf);
			return (-1);
		}
		if_count++;
	}

	free(buf);
	return (if_count);
}

static int set_encryption_filter(const char * input)
{
	if (input == NULL) return (1);

	if (strlen(input) < 3) return (1);

	if (strcasecmp(input, "opn") == 0) lopt.f_encrypt |= STD_OPN;

	if (strcasecmp(input, "wep") == 0) lopt.f_encrypt |= STD_WEP;

	if (strcasecmp(input, "wpa") == 0)
	{
		lopt.f_encrypt |= STD_WPA;
		lopt.f_encrypt |= STD_WPA2;
		lopt.f_encrypt |= AUTH_SAE;
	}

	if (strcasecmp(input, "wpa1") == 0) lopt.f_encrypt |= STD_WPA;

	if (strcasecmp(input, "wpa2") == 0) lopt.f_encrypt |= STD_WPA2;

	if (strcasecmp(input, "wpa3") == 0) lopt.f_encrypt |= AUTH_SAE;

	if (strcasecmp(input, "owe") == 0) lopt.f_encrypt |= AUTH_OWE;

	return (0);
}

static int check_monitor(struct wif * wi[], int * fd_raw, int * fdh, int cards)
{
	int i, monitor;
	char ifname[64];

	for (i = 0; i < cards; i++)
	{
		monitor = wi_get_monitor(wi[i]);
		if (monitor != 0)
		{
			memset(lopt.message, '\x00', sizeof(lopt.message));
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ %s reset to monitor mode",
					 wi_get_ifname(wi[i]));
			// reopen in monitor mode

			strlcpy(ifname, wi_get_ifname(wi[i]), sizeof(ifname));

			wi_close(wi[i]);
			wi[i] = wi_open(ifname);
			if (!wi[i])
			{
				printf("Can't reopen %s\n", ifname);
				exit(1);
			}

			fd_raw[i] = wi_fd(wi[i]);
			if (fd_raw[i] > *fdh) *fdh = fd_raw[i];
		}
	}
	return (0);
}

static int check_channel(struct wif * wi[], int cards)
{
	int i, chan;
	for (i = 0; i < cards; i++)
	{
		chan = wi_get_channel(wi[i]);
		if (opt.ignore_negative_one == 1 && chan == -1) return (0);
		if (lopt.channel[i] != chan)
		{
			memset(lopt.message, '\x00', sizeof(lopt.message));
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ fixed channel %s: %d ",
					 wi_get_ifname(wi[i]),
					 chan);
#ifdef CONFIG_LIBNL
			wi_set_ht_channel(wi[i], lopt.channel[i], lopt.htval);
#else
			wi_set_channel(wi[i], lopt.channel[i]);
#endif
		}
	}
	return (0);
}

static int check_frequency(struct wif * wi[], int cards)
{
	int i, freq;
	for (i = 0; i < cards; i++)
	{
		freq = wi_get_freq(wi[i]);
		if (freq < 0) continue;
		if (lopt.frequency[i] != freq)
		{
			memset(lopt.message, '\x00', sizeof(lopt.message));
			snprintf(lopt.message,
					 sizeof(lopt.message),
					 "][ fixed frequency %s: %d ",
					 wi_get_ifname(wi[i]),
					 freq);
			wi_set_freq(wi[i], lopt.frequency[i]);
		}
	}
	return (0);
}

static int detect_frequencies(struct wif * wi)
{
	REQUIRE(wi != NULL);

	int start_freq = 2192;
	int end_freq = 2732;
	int max_freq_num = 2048; // should be enough to keep all available channels
	int freq = 0, i = 0;

	printf("Checking available frequencies, this could take few seconds.\n");

	frequencies = (int *) malloc(
		(max_freq_num + 1) * sizeof(int)); // field for frequencies supported
	ALLEGE(frequencies != NULL);
	memset(frequencies, 0, (max_freq_num + 1) * sizeof(int));
	for (freq = start_freq; freq <= end_freq; freq += 5)
	{
		if (wi_set_freq(wi, freq) == 0)
		{
			frequencies[i] = freq;
			i++;
		}
		if (freq == 2482)
		{
			// special case for chan 14, as its 12MHz away from 13, not 5MHz
			freq = 2484;
			if (wi_set_freq(wi, freq) == 0)
			{
				frequencies[i] = freq;
				i++;
			}
			freq = 2482;
		}
	}

	// again for 5GHz & 6GHz channels
	start_freq = 4800;
	end_freq = 7115;
	for (freq = start_freq; freq <= end_freq; freq += 5)
	{
		if (wi_set_freq(wi, freq) == 0)
		{
			frequencies[i] = freq;
			i++;
		}
	}

	printf("Done.\n");
	return (0);
}

static int array_contains(const int * array, int length, int value)
{
	REQUIRE(array != NULL);
	REQUIRE(length >= 0 && length < INT_MAX);

	int i;
	for (i = 0; i < length; i++)
		if (array[i] == value) return (1);

	return (0);
}

static int rearrange_frequencies(void)
{
	int * freqs;
	int count, left, pos;
	int width, last_used = 0;
	int cur_freq, round_done;

	width = DEFAULT_CWIDTH;

	count = getfreqcount(0);
	left = count;
	pos = 0;

	freqs = malloc(sizeof(int) * (count + 1));
	ALLEGE(freqs != NULL);
	memset(freqs, 0, sizeof(int) * (count + 1));
	round_done = 0;

	while (left > 0)
	{
		cur_freq = lopt.own_frequencies[pos % count];

		if (cur_freq == last_used) round_done = 1;

		if (((count - left) > 0) && !round_done
			&& (ABS(last_used - cur_freq) < width))
		{
			pos++;
			continue;
		}

		if (!array_contains(freqs, count, cur_freq))
		{
			freqs[count - left] = cur_freq;
			last_used = cur_freq;
			left--;
			round_done = 0;
		}

		pos++;
	}

	memcpy(lopt.own_frequencies, freqs, count * sizeof(int));
	free(freqs);

	return (0);
}

int main(int argc, char * argv[])
{
	long time_slept, cycle_time, cycle_time2;
	char * output_format_string;
	int caplen = 0, i, j, fdh, chan_count, freq_count;
	int fd_raw[MAX_CARDS];
	int ivs_only, found;
	int freq[3];
	int band_ax_only = 0;
	int num_opts = 0;
	int option = 0;
	int option_index = 0;
	char ifnam[64];
	int wi_read_failed = 0;
	int n = 0;
	int output_format_first_time = 1;
	char freq_string[MAX_FREQS * MAX_FREQ_STR_LEN] = {0};

#ifdef HAVE_PCRE
	const char * pcreerror;
	int pcreerroffset;
#endif

	struct AP_info *ap_cur, *ap_next;
	struct ST_info *st_cur, *st_next;
	struct NA_info *na_cur, *na_next;
	struct oui *oui_cur, *oui_next;

	struct pcap_pkthdr pkh;

	time_t tt1, tt2, start_time;

	struct wif * wi[MAX_CARDS];
	struct rx_info ri;
	g_wi = wi;
	
	unsigned char tmpbuf[4096];
	unsigned char buffer[4096];
	unsigned char * h80211;
	char * iface[MAX_CARDS];

	struct timeval tv0;
	struct timeval tv1;
	struct timeval tv2;
	struct timeval tv3;
	struct timeval tv4;
	struct tm * lt;

	/*
	struct sockaddr_in provis_addr;
	*/

	fd_set rfds;

	static const struct option long_options[]
		= {{"ht20", 0, 0, '2'},
		   {"ht40-", 0, 0, '3'},
		   {"ht40+", 0, 0, '5'},
		   {"band", 1, 0, 'b'},
		   {"beacon", 0, 0, 'e'},
		   {"beacons", 0, 0, 'e'},
		   {"cswitch", 1, 0, 's'},
		   {"netmask", 1, 0, 'm'},
		   {"bssid", 1, 0, 'd'},
		   {"essid", 1, 0, 'N'},
		   {"essid-regex", 1, 0, 'R'},
		   {"channel", 1, 0, 'c'},
		   {"gpsd", 0, 0, 'g'},
		   {"ivs", 0, 0, 'i'},
		   {"write", 1, 0, 'w'},
		   {"encrypt", 1, 0, 't'},
		   {"update", 1, 0, 'u'},
		   {"berlin", 1, 0, 'B'},
		   {"help", 0, 0, 'H'},
		   {"nodecloak", 0, 0, 'D'},
		   {"showack", 0, 0, 'A'},
		   {"detect-anomaly", 0, 0, 'E'},
		   {"output-format", 1, 0, 'o'},
		   {"ignore-negative-one", 0, &opt.ignore_negative_one, 1},
		   {"manufacturer", 0, 0, 'M'},
		   {"uptime", 0, 0, 'U'},
		   {"write-interval", 1, 0, 'I'},
		   {"wps", 0, 0, 'W'},
		   {"background", 1, 0, 'K'},
		   {"min-packets", 1, 0, 'n'},
		   {"real-time", 0, 0, 'T'},
		   {"80211ax", 0, 0, 'X'},
		   {"ppi", 0, 0, 'p'},
		   {"coords", 1, 0, 'y'},
		   {"target", 1, 0, 'z'},
		   {"tcp-server", 1, 0, 'V'},
		   {"probes", 0, 0, 'P'},
		   {"legacy-ui", 0, 0, 'L'},
		   {"ax40", 0, 0, '4'},
		   {"ax80", 0, 0, '8'},
		   {"ax80+", 0, 0, '9'},
		   {"ax160", 0, 0, '6'},
		   {"cseg0", 1, 0, '0'},
		   {"cseg1", 1, 0, '1'},
		   {0, 0, 0, 0}};

	main_pid = getpid();

	console_utf8_enable();
	ac_crypto_init();

	ALLEGE(pthread_mutex_init(&(lopt.mx_print), NULL) == 0);
	ALLEGE(pthread_mutex_init(&(lopt.mx_sort), NULL) == 0);

	textstyle(TEXT_RESET); //(TEXT_RESET, TEXT_BLACK, TEXT_WHITE);

	/* initialize a bunch of variables */

	rand_init();
	memset(&opt, 0, sizeof(opt));
	memset(&lopt, 0, sizeof(lopt));

	h80211 = NULL;
	ivs_only = 0;
	lopt.chanoption = 0;
	lopt.freqoption = 0;
	lopt.num_cards = 0;
	fdh = 0;
	time_slept = 0;
	lopt.batt = NULL;
	lopt.chswitch = 0;
	opt.usegpsd = 0;
	lopt.channels = (int *) bg_chans;
	lopt.band_support_mask = 0;
	lopt.one_beacon = 1;
	lopt.singlechan = 0;
	lopt.singlefreq = 0;
	lopt.dump_prefix = NULL;
	opt.record_data = 0;
	opt.f_cap = NULL;
	opt.f_ivs = NULL;
	opt.f_txt = NULL;
	opt.f_kis = NULL;
	opt.f_kis_xml = NULL;
	opt.f_gps = NULL;
	opt.f_logcsv = NULL;
	opt.f_probes = NULL;
	lopt.keyout = NULL;
	opt.f_xor = NULL;
	opt.sk_len = 0;
	opt.sk_len2 = 0;
	opt.sk_start = 0;
	opt.prefix = NULL;
	lopt.f_encrypt = 0;
	lopt.asso_client = 0;
	lopt.f_essid = NULL;
	lopt.f_essid_count = 0;
	lopt.active_scan_sim = 0;
	lopt.update_s = 0;
	lopt.decloak = 1;
	lopt.is_berlin = 0;
	lopt.numaps = 0;
	lopt.maxnumaps = 0;
	lopt.berlin = 120;
	lopt.show_ap = 1;
	lopt.show_sta = 1;
	lopt.show_ack = 0;
	lopt.hide_known = 0;
	lopt.maxsize_essid_seen = 5; // Initial value: length of "ESSID"
	lopt.show_manufacturer = 0;
	lopt.show_uptime = 0;
	lopt.hopfreq = DEFAULT_HOPFREQ;
	opt.s_file = NULL;
	lopt.s_iface = NULL;
	lopt.f_cap_in = NULL;
	lopt.detect_anomaly = 0;
	lopt.airodump_start_time = NULL;
	lopt.manufList = NULL;

	opt.output_format_pcap = 1;
	opt.output_format_csv = 1;
	opt.output_format_kismet_csv = 1;
	opt.output_format_kismet_netxml = 1;
	opt.output_format_log_csv = 1;
	opt.output_format_probes = 0;
	lopt.gps_valid_interval
		= 5; // If we dont get a new GPS update in 5 seconds - invalidate it
	lopt.file_write_interval = 5; // Write file every 5 seconds by default
	lopt.maxsize_wps_seen = 6;
	lopt.show_wps = 0;
	lopt.background_mode = -1;
	lopt.do_exit = 0;
	lopt.min_pkts = 2;
	lopt.relative_time = 0;
	lopt.scan_11ax = 0;
	lopt.band_support_mask = -1;
	lopt.target = 0;
	lopt.ppi = 0;
	lopt.coordinates[0] = 0;
	lopt.coordinates[1] = 0;
	strlcpy(lopt.ip, "0.0.0.0", sizeof(lopt.ip));
	lopt.port = 23456;
	lopt.tcp_sock_fd = -1;
	lopt.ax_bw = 0; // can be 4 (40MHz), 8 (80MHz), 9 (80+80), 6 (160MHz)
	lopt.c_seg0 = 0;
	lopt.c_seg1 = 0;

#ifdef CONFIG_LIBNL
	lopt.htval = CHANNEL_NO_HT;
#endif
#ifdef HAVE_PCRE
	lopt.f_essid_regex = NULL;
#endif

	// Default selection.
	resetSelection();

	memset(opt.sharedkey, '\x00', sizeof(opt.sharedkey));
	memset(lopt.message, '\x00', sizeof(lopt.message));
	memset(&lopt.pfh_in, '\x00', sizeof(struct pcap_file_header));

	gettimeofday(&tv0, NULL);

	lt = localtime(&tv0.tv_sec);

	lopt.keyout = (char *) malloc(512);
	ALLEGE(lopt.keyout != NULL);
	memset(lopt.keyout, 0, 512);
	snprintf(lopt.keyout,
			 511,
			 "keyout-%02d%02d-%02d%02d%02d.keys",
			 lt->tm_mon + 1,
			 lt->tm_mday,
			 lt->tm_hour,
			 lt->tm_min,
			 lt->tm_sec);

	for (i = 0; i < MAX_CARDS; i++)
	{
		fd_raw[i] = -1;
		lopt.channel[i] = 0;
	}

	memset(opt.f_bssid, '\x00', 6);
	memset(opt.f_netmask, '\x00', 6);
	memset(lopt.wpa_bssid, '\x00', 6);

	/* check the arguments */

	for (i = 0; long_options[i].name != NULL; i++)
		;
	num_opts = i;

	for (i = 0; i < argc; i++) // go through all arguments
	{
		found = 0;
		if (strlen(argv[i]) >= 3)
		{
			if (argv[i][0] == '-' && argv[i][1] != '-')
			{
				// we got a single dash followed by at least 2 chars
				// lets check that against our long options to find errors
				for (j = 0; j < num_opts; j++)
				{
					if (strcmp(argv[i] + 1, long_options[j].name) == 0)
					{
						// found long option after single dash
						found = 1;
						if (i > 1 && strcmp(argv[i - 1], "-") == 0)
						{
							// separated dashes?
							printf("Notice: You specified \"%s %s\". Did you "
								   "mean \"%s%s\" instead?\n",
								   argv[i - 1],
								   argv[i],
								   argv[i - 1],
								   argv[i]);
						}
						else
						{
							// forgot second dash?
							printf("Notice: You specified \"%s\". Did you mean "
								   "\"-%s\" instead?\n",
								   argv[i],
								   argv[i]);
						}
						break;
					}
				}
				if (found)
				{
					sleep(3);
					break;
				}
			}
		}
	}

	do
	{
		option_index = 0;

		option
			= getopt_long(argc,
						  argv,
						  "b:c:egiw:s:t:u:m:d:N:R:aHDB:Ahf:r:EC:o:x:MUI:WK:n:T:Xpz:y:V:P",
						  long_options,
						  &option_index);

		if (option < 0) break;

		switch (option)
		{
			case 0:

				break;

			case ':':
			case '?':

				printf("\"%s --help\" for help.\n", argv[0]);
				return (EXIT_FAILURE);

			case 'K':
			{
				char * invalid_str = NULL;
				long int bg_mode = strtol(optarg, &invalid_str, 10);
				if ((invalid_str && *invalid_str != 0)
					|| !(bg_mode == 0 || bg_mode == 1))
				{
					printf("Invalid background mode. Must be '0' or '1'\n");
					exit(EXIT_FAILURE);
				}
				lopt.background_mode = (char) bg_mode;
				break;
			}
			case 'I':

				if (!is_string_number(optarg))
				{
					printf("Error: Write interval is not a number (>0). "
						   "Aborting.\n");
					exit(EXIT_FAILURE);
				}

				lopt.file_write_interval = (int) strtol(optarg, NULL, 10);

				if (lopt.file_write_interval <= 0)
				{
					printf("Error: Write interval must be greater than 0. "
						   "Aborting.\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'T':
				lopt.relative_time = 1;
				break;

			case 'E':
				lopt.detect_anomaly = 1;
				break;

			case 'e':

				lopt.one_beacon = 0;
				break;

			case 'a':

				lopt.asso_client = 1;
				break;

			case 'A':

				lopt.show_ack = 1;
				break;

			case 'h':

				lopt.hide_known = 1;
				break;

			case 'D':

				lopt.decloak = 0;
				break;

			case 'M':

				lopt.show_manufacturer = 1;
				break;

			case 'U':

				lopt.show_uptime = 1;
				break;

			case 'W':

				lopt.show_wps = 1;
				break;
			
			case 'X':

    			// Set a flag indicating that 802.11ax scanning is selected
    			lopt.scan_11ax = 1;
    			break;

			case 'c':

				if (lopt.channel[0] > 0 || lopt.chanoption == 1)
				{
					if (lopt.chanoption == 1)
						printf("Notice: Channel range already given\n");
					else
						printf("Notice: Channel already given (%d)\n", lopt.channel[0]);
					break;
				}

				lopt.channel[0] = getchannels(optarg);

				if (lopt.channel[0] < 0)
				{
					airodump_usage();
					return (EXIT_FAILURE);
				}

				// if getchannels returns 0, that means we had a channel list
				if (lopt.channel[0] == 0) {
					lopt.channels = lopt.own_channels;
				} else { // otherwise we just had a single channel
					lopt.channels = lopt.channel;
				}

				if (lopt.scan_11ax) {
					// Convert the channel array to frequency string for 6 GHz channels
					// Function to be implemented: channels_to_freq_string_ax(lopt.channel, lopt.freqstring);
					// For now, assuming the function fills lopt.freqstring appropriately
					channels_to_freq_string_ax(lopt.channels, freq_string);

					freq_string[sizeof(freq_string) - 1] = '\0';

					lopt.chanoption = 0; // Reset channel option
					lopt.freqoption = 1; // Set frequency option
					lopt.freqstring = freq_string;
					break;
				} else {
					lopt.chanoption = 1;
					break;
				}
				lopt.channels = (int *) bg_chans; // Use standard channel set
				break;

			case 'C':

				if (lopt.channel[0] > 0 || lopt.chanoption == 1)
				{
					if (lopt.chanoption == 1)
						printf("Notice: Channel range already given\n");
					else
						printf("Notice: Channel already given (%d)\n",
							   lopt.channel[0]);
					break;
				}

				if (lopt.freqoption == 1)
				{
					printf("Notice: Frequency range already given\n");
					break;
				}

				lopt.freqstring = optarg;

				lopt.freqoption = 1;

				break;

			case 'b':
				freq[0] = freq[1] = freq[2] = 0; // freq[0] for b/g, freq[1] for a, freq[2] for ax

				for (i = 0; i < (int) strlen(optarg); i++) //-V814
				{
					if (optarg[i] == 'a')
						freq[1] = 1;
					else if (optarg[i] == 'b' || optarg[i] == 'g')
						freq[0] = 1;
					else if (optarg[i] == 'x')
						freq[2] = 1;
					else
					{
						printf("Error: invalid band (%c)\n", optarg[i]);
						printf("\"%s --help\" for help.\n", argv[0]);
						exit(EXIT_FAILURE);
					}
				}

				// Check if 'ax' band is specified
				if (freq[2] == 1) {
					band_ax_only = (freq[0] == 0 && freq[1] == 0);
					lopt.scan_11ax = 1;

					// Accumulate frequencies from specified bands
					if (freq[0] == 1)
						channels_to_freq_string_bg(bg_chans, freq_string); // Append bg frequencies
					if (freq[1] == 1)
						channels_to_freq_string_a(a_chans, freq_string); // Append a frequencies
					channels_to_freq_string_ax(ax_chans, freq_string); // Append ax frequencies

					freq_string[sizeof(freq_string) - 1] = '\0';

					lopt.freqstring = freq_string;
					
					lopt.chanoption = 0; // Reset channel option
					lopt.freqoption = 1; // Set frequency option
				} else {
					// Maintain default behavior for setting lopt.channels
					if (freq[1] + freq[0] == 2)
						lopt.channels = (int *) abg_chans;
					else if (freq[1] == 1)
						lopt.channels = (int *) a_chans;
					else
						lopt.channels = (int *) bg_chans;
					lopt.chanoption = 1;
				}
				break;

			case 'z':
				if (num_targets >= MAX_TARGETS) {
					fprintf(stderr, "Too many target MACs (max %d).\n", MAX_TARGETS);
					return EXIT_FAILURE;
				}

				if (convertMACToBytesWithWildcards(optarg, targets[num_targets], wildcard_nibbles[num_targets]) == 0) {

					num_targets++;
				} else if (parseMACAddressFile(optarg) != 0) {
					fprintf(stderr, "Invalid MAC address or file error.\n");
					return EXIT_FAILURE;
				}

				lopt.target = 1;
				color_on();
				snprintf(lopt.message, sizeof(lopt.message), "][ targeting on");
				break;

			case 'y':
				if (optarg[0] == '-') {
					fprintf(stderr, "You must pass coordinates when using the --coord option.\n");
					exit(EXIT_FAILURE);
				}
				// Attempt to parse latitude and longitude
				if (sscanf(optarg, "%lf,%lf", &lopt.coordinates[0], &lopt.coordinates[1]) == 2) {
					// Validate latitude and longitude
					if (lopt.coordinates[0] < -90.0 || lopt.coordinates[0] > 90.0 ||
						lopt.coordinates[1] < -180.0 || lopt.coordinates[1] > 180.0) {
						fprintf(stderr, "Invalid coordinates: %s\n", optarg);
						exit(EXIT_FAILURE);
					}
				} else {
					fprintf(stderr, "Invalid format for coordinates: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				size_t y_len = strlen(lopt.message);
    			snprintf(lopt.message + y_len, sizeof(lopt.message) - y_len, " ][ Fixed Coords %.6f,%.6f", lopt.coordinates[0], lopt.coordinates[1]);
				
				break;

			case 'V':

				if (!validate_ip_port(optarg)) {
					fprintf(stderr, "Invalid server address format!\n");
					exit(EXIT_FAILURE);
				}
				lopt.tcp_sock_fd = 0;
				size_t V_len = strlen(lopt.message);
    			snprintf(lopt.message + V_len, sizeof(lopt.message) - V_len, " ][ TCP Server On %s:%d", lopt.ip, lopt.port);
				break;

			case 'P':

				opt.record_data = 1;
				opt.output_format_probes = 1;
				break;

			case 'L':
				force_legacy_ui = 1;
				break;

			case 'i':

				// Reset output format if it's the first time the option is
				// specified
				if (output_format_first_time)
				{
					output_format_first_time = 0;

					opt.output_format_pcap = 0;
					opt.output_format_csv = 0;
					opt.output_format_kismet_csv = 0;
					opt.output_format_kismet_netxml = 0;
					opt.output_format_log_csv = 0;
				}

				if (opt.output_format_pcap)
				{
					airodump_usage();
					fprintf(stderr,
							"Invalid output format: IVS and PCAP "
							"format cannot be used together.\n");
					return (EXIT_FAILURE);
				}

				ivs_only = 1;
				break;

			case 'g':

				opt.usegpsd = 1;
				break;

			case 'p':
				
				lopt.ppi = 1;
				break;

			case 'w':

				if (lopt.dump_prefix != NULL)
				{
					printf("Notice: dump prefix already given\n");
					break;
				}
				/* Write prefix */
				lopt.dump_prefix = optarg;
				opt.record_data = 1;
				break;

			case 'r':

				if (opt.s_file)
				{
					printf("Packet source already specified.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				opt.s_file = optarg;
				break;

			case 's':

				if (strtol(optarg, NULL, 10) > 2 || errno == EINVAL)
				{
					airodump_usage();
					return (EXIT_FAILURE);
				}
				if (lopt.chswitch != 0)
				{
					printf("Notice: switching method already given\n");
					break;
				}
				lopt.chswitch = (int) strtol(optarg, NULL, 10);
				break;

			case 'u':

				lopt.update_s = (int) strtol(optarg, NULL, 10);

				/* If failed to parse or value <= 0, use default, 100ms */
				if (lopt.update_s <= 0) lopt.update_s = REFRESH_RATE;

				break;

			case 'f':

				lopt.hopfreq = (int) strtol(optarg, NULL, 10);

				/* If failed to parse or value <= 0, use default, 100ms */
				if (lopt.hopfreq <= 0) lopt.hopfreq = DEFAULT_HOPFREQ;

				break;

			case 'B':

				lopt.is_berlin = 1;
				lopt.berlin = (int) strtol(optarg, NULL, 10);

				if (lopt.berlin <= 0) lopt.berlin = 120;

				break;

			case 'm':

				if (memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
				{
					printf("Notice: netmask already given\n");
					break;
				}
				if (getmac(optarg, 1, opt.f_netmask) != 0)
				{
					printf("Notice: invalid netmask\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return (EXIT_FAILURE);
				}
				break;

			case 'd':

				if (memcmp(opt.f_bssid, NULL_MAC, 6) != 0)
				{
					printf("Notice: bssid already given\n");
					break;
				}
				if (getmac(optarg, 1, opt.f_bssid) != 0)
				{
					printf("Notice: invalid bssid\n");
					printf("\"%s --help\" for help.\n", argv[0]);

					return (EXIT_FAILURE);
				}
				break;

			case 'N':

				lopt.f_essid_count++;
				lopt.f_essid = (char **) realloc( //-V701
					lopt.f_essid,
					lopt.f_essid_count * sizeof(char *));
				ALLEGE(lopt.f_essid != NULL);
				lopt.f_essid[lopt.f_essid_count - 1] = optarg;
				break;

			case 'R':

#ifdef HAVE_PCRE
				if (lopt.f_essid_regex != NULL)
				{
					printf("Error: ESSID regular expression already given. "
						   "Aborting\n");
					exit(EXIT_FAILURE);
				}

				lopt.f_essid_regex
					= pcre_compile(optarg, 0, &pcreerror, &pcreerroffset, NULL);

				if (lopt.f_essid_regex == NULL)
				{
					printf("Error: regular expression compilation failed at "
						   "offset %d: %s; aborting\n",
						   pcreerroffset,
						   pcreerror);
					exit(EXIT_FAILURE);
				}
#else
				printf("Error: Airodump-ng wasn't compiled with PCRE support; "
					   "aborting\n");
#endif

				break;

			case 't':

				set_encryption_filter(optarg);
				break;

			case 'n':

				lopt.min_pkts = strtoul(optarg, NULL, 10);
				break;

			case 'o':

				// Reset output format if it's the first time the option is
				// specified
				if (output_format_first_time)
				{
					output_format_first_time = 0;

					opt.output_format_pcap = 0;
					opt.output_format_csv = 0;
					opt.output_format_kismet_csv = 0;
					opt.output_format_kismet_netxml = 0;
					opt.output_format_log_csv = 0;
				}

				// Parse the value
				output_format_string = strtok(optarg, ",");
				while (output_format_string != NULL)
				{
					if (*output_format_string != '\0')
					{
						if (strncasecmp(output_format_string, "csv", 3) == 0
							|| strncasecmp(output_format_string, "txt", 3) == 0)
						{
							opt.output_format_csv = 1;
						}
						else if (strncasecmp(output_format_string, "pcap", 4)
									 == 0
								 || strncasecmp(output_format_string, "cap", 3)
										== 0)
						{
							if (ivs_only)
							{
								airodump_usage();
								fprintf(stderr,
										"Invalid output format: IVS "
										"and PCAP format cannot be "
										"used together.\n");
								return (EXIT_FAILURE);
							}
							opt.output_format_pcap = 1;
						}
						else if (strncasecmp(output_format_string, "ivs", 3)
								 == 0)
						{
							if (opt.output_format_pcap)
							{
								airodump_usage();
								fprintf(stderr,
										"Invalid output format: IVS "
										"and PCAP format cannot be "
										"used together.\n");
								return (EXIT_FAILURE);
							}
							ivs_only = 1;
						}
						else if (strncasecmp(output_format_string, "kismet", 6)
								 == 0)
						{
							opt.output_format_kismet_csv = 1;
						}
						else if (strncasecmp(output_format_string, "gps", 3)
								 == 0)
						{
							opt.usegpsd = 1;
						}
						else if (strncasecmp(output_format_string, "netxml", 6)
									 == 0
								 || strncasecmp(
										output_format_string, "newcore", 7)
										== 0
								 || strncasecmp(
										output_format_string, "kismet-nc", 9)
										== 0
								 || strncasecmp(
										output_format_string, "kismet_nc", 9)
										== 0
								 || strncasecmp(output_format_string,
												"kismet-newcore",
												14)
										== 0
								 || strncasecmp(output_format_string,
												"kismet_newcore",
												14)
										== 0)
						{
							opt.output_format_kismet_netxml = 1;
						}
						else if (strncasecmp(output_format_string, "logcsv", 6)
								 == 0)
						{
							opt.output_format_log_csv = 1;
						}
						else if (strncasecmp(output_format_string, "default", 7)
								 == 0)
						{
							opt.output_format_pcap = 1;
							opt.output_format_csv = 1;
							opt.output_format_kismet_csv = 1;
							opt.output_format_kismet_netxml = 1;
						}
						else if (strncasecmp(output_format_string, "none", 4)
								 == 0)
						{
							opt.output_format_pcap = 0;
							opt.output_format_csv = 0;
							opt.output_format_kismet_csv = 0;
							opt.output_format_kismet_netxml = 0;
							opt.output_format_log_csv = 0;
							opt.usegpsd = 0;
							ivs_only = 0;
						}
						else
						{
							// Display an error if it does not match any value
							fprintf(stderr,
									"Invalid output format: <%s>\n",
									output_format_string);
							exit(EXIT_FAILURE);
						}
					}
					output_format_string = strtok(NULL, ",");
				}

				break;

			case 'H':
				airodump_usage();
				return (EXIT_FAILURE);

			case 'x':

				lopt.active_scan_sim = (int) strtol(optarg, NULL, 10);

				if (lopt.active_scan_sim <= 0) lopt.active_scan_sim = 0;
				break;
			case '0':
#ifndef CONFIG_LIBNL
				printf("AX Center Segment 0 unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.c_seg0 = strtoul(optarg, NULL, 10);
#endif
				break;
			case '1':
#ifndef CONFIG_LIBNL
				printf("AX Center Segment 1 unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.c_seg1 = strtoul(optarg, NULL, 10);
#endif
				break;
			case '2':
#ifndef CONFIG_LIBNL
				printf("HT Channel unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.htval = CHANNEL_HT20;
#endif
				break;
			case '3':
#ifndef CONFIG_LIBNL
				printf("HT Channel unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.htval = CHANNEL_HT40_MINUS;
#endif
				break;
			case '5':
#ifndef CONFIG_LIBNL
				printf("HT Channel unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.htval = CHANNEL_HT40_PLUS;
#endif
				break;
			case '4':
#ifndef CONFIG_LIBNL
				printf("AX 40 MHz Bandwidth unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.ax_bw = CHANNEL_AX40;
#endif
				break;
			case '8':
#ifndef CONFIG_LIBNL
				printf("AX 80 MHz Bandwidth unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.ax_bw = CHANNEL_AX80;
#endif
				break;
			case '9':
#ifndef CONFIG_LIBNL
				printf("AX 80+80 MHz Bandwidth unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.ax_bw = CHANNEL_AX80_80;
#endif
				break;
			case '6':
#ifndef CONFIG_LIBNL
				printf("AX 160 MHz Bandwidth unsupported\n");
				return (EXIT_FAILURE);
#else
				lopt.ax_bw = CHANNEL_AX160;
#endif
				break;
			default:
				airodump_usage();
				return (EXIT_FAILURE);
		}
		
	} while (1);
	
	if (argc - optind != 1 && opt.s_file == NULL)
	{
		if (argc == 1)
		{
			airodump_usage();
		}
		if (argc - optind == 0)
		{
			printf("No interface specified.\n");
		}
		if (argc > 1)
		{
			printf("\"%s --help\" for help.\n", argv[0]);
		}
		return (EXIT_FAILURE);
	}

	if (argc - optind == 1) lopt.s_iface = argv[argc - 1];

	if ((memcmp(opt.f_netmask, NULL_MAC, 6) != 0)
		&& (memcmp(opt.f_bssid, NULL_MAC, 6) == 0))
	{
		printf("Notice: specify bssid \"--bssid\" with \"--netmask\"\n");
		printf("\"%s --help\" for help.\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (lopt.show_wps && lopt.show_manufacturer)
		lopt.maxsize_essid_seen += lopt.maxsize_wps_seen;

	lopt.band_mode = infer_band_mode();

	if (lopt.s_iface != NULL)
	{
		/* initialize cards */
		lopt.num_cards = init_cards(lopt.s_iface, iface, wi);

		if (lopt.num_cards <= 0 || lopt.num_cards >= MAX_CARDS)
		{
			printf("Failed initializing wireless card(s): %s\n", lopt.s_iface);
			return (EXIT_FAILURE);
		}

		for (i = 0; i < lopt.num_cards; i++)
		{
			fd_raw[i] = wi_fd(wi[i]);
			if (fd_raw[i] > fdh) fdh = fd_raw[i];
		}

		lopt.band_support_mask = band_support_mask_for_cards(wi, lopt.num_cards);
		if (lopt.band_support_mask >= 0 && !band_mode_is_supported(lopt.band_mode))
		{
			int fallback_band_mode = next_supported_band_mode(lopt.band_mode, 1);

			if (fallback_band_mode != lopt.band_mode)
			{
				if (fallback_band_mode == BAND_MODE_AX)
				{
					if (lopt.own_frequencies != NULL)
					{
						free(lopt.own_frequencies);
						lopt.own_frequencies = NULL;
					}
					if (!build_ax_frequency_list(&lopt.own_frequencies))
					{
						printf("No valid 6 GHz frequencies available.\n");
						return (EXIT_FAILURE);
					}
					lopt.freqoption = 1;
					lopt.chanoption = 0;
					lopt.channels = (int *) ax_chans;
					lopt.scan_11ax = 1;
					lopt.freqstring = NULL;
				}
				else
				{
					lopt.channels = (fallback_band_mode == BAND_MODE_A)
									 ? (int *) a_chans
									 : (int *) bg_chans;
					lopt.freqoption = 0;
					lopt.chanoption = 1;
					lopt.scan_11ax = 0;
					lopt.freqstring = NULL;
					if (lopt.own_frequencies != NULL)
					{
						free(lopt.own_frequencies);
						lopt.own_frequencies = NULL;
					}
				}
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ %s unsupported; using %s",
						 band_mode_label(lopt.band_mode),
						 band_mode_label(fallback_band_mode));
				append_tui_message_history(lopt.message, time(NULL));
				lopt.band_mode = fallback_band_mode;
			}
			else
			{
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ no supported bands available");
				append_tui_message_history(lopt.message, time(NULL));
			}
		}

		if (lopt.freqoption == 1 && lopt.freqstring != NULL) // use frequencies
		{
			if (band_ax_only)
			{
				if (!build_ax_frequency_list(&lopt.own_frequencies))
				{
					printf("No valid 6 GHz frequencies available.\n");
					return (EXIT_FAILURE);
				}
				lopt.frequency[0] = 0;
			}
			else
			{
				detect_frequencies(wi[0]);
				lopt.frequency[0] = getfrequencies(lopt.freqstring);
				if (lopt.frequency[0] == -1)
				{
					printf("No valid frequency given.\n");
					return (EXIT_FAILURE);
				}
			}

			rearrange_frequencies();

			freq_count = getfreqcount(0);

			/* find the interface index */
			/* start a child to hop between frequencies */

			if (lopt.frequency[0] == 0)
			{
				IGNORE_NZ(pipe(lopt.ch_pipe));
				IGNORE_NZ(pipe(lopt.cd_pipe));
				set_hopper_pipe_nonblocking();

				struct sigaction action;
				action.sa_flags = 0;
				action.sa_handler = &sighandler;
				sigemptyset(&action.sa_mask);

				if (sigaction(SIGUSR1, &action, NULL) == -1)
					perror("sigaction(SIGUSR1)");
				hopper_pipe_ready = 1;

				reset_hopper_reject_state();
				hopper_reject_total = freq_count;
				hopper_pid = fork();
				if (hopper_pid == 0)
				{
					/* reopen cards.  This way parent & child don't share
					* resources for
					* accessing the card (e.g. file descriptors) which may cause
					* problems.  -sorbo
					*/
					for (i = 0; i < lopt.num_cards; i++)
					{
						strlcpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam));

						wi_close(wi[i]);
						wi[i] = wi_open(ifnam);
						if (!wi[i])
						{
							printf("Can't reopen %s\n", ifnam);
							exit(EXIT_FAILURE);
						}
					}

					/* Drop privileges */
					if (setuid(getuid()) == -1)
					{
						perror("setuid");
					}

					frequency_hopper(wi, lopt.num_cards, freq_count, main_pid);
					exit(EXIT_FAILURE);
				}
				else if (hopper_pid < 0)
				{
					perror("fork");
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				for (i = 0; i < lopt.num_cards; i++)
				{
#ifdef CONFIG_LIBNL
					int result;
					result = wi_set_freq_ax(wi[i], lopt.frequency[0], lopt.ax_bw, lopt.c_seg0, lopt.c_seg1);
					if (result != 0) {
						exit(EXIT_FAILURE);
					}
#else
					wi_set_freq(wi[i], lopt.frequency[0]);
#endif
					lopt.frequency[i] = lopt.frequency[0];
				}
				lopt.singlefreq = 1;
			}
		}
		else // use channels
		{
			chan_count = getchancount(0);

			/* find the interface index */
			/* start a child to hop between channels */

			if (lopt.channel[0] == 0)
			{
				IGNORE_NZ(pipe(lopt.ch_pipe));
				IGNORE_NZ(pipe(lopt.cd_pipe));
				set_hopper_pipe_nonblocking();

				struct sigaction action;
				action.sa_flags = 0;
				action.sa_handler = &sighandler;
				sigemptyset(&action.sa_mask);

				if (sigaction(SIGUSR1, &action, NULL) == -1)
					perror("sigaction(SIGUSR1)");
				hopper_pipe_ready = 1;

				reset_hopper_reject_state();
				hopper_reject_total = chan_count;
				hopper_pid = fork();
				if (hopper_pid == 0)
				{
					/* reopen cards.  This way parent & child don't share
					* resources for
					* accessing the card (e.g. file descriptors) which may cause
					* problems.  -sorbo
					*/
					for (i = 0; i < lopt.num_cards; i++)
					{
						strlcpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam));

						wi_close(wi[i]);
						wi[i] = wi_open(ifnam);
						if (!wi[i])
						{
							printf("Can't reopen %s\n", ifnam);
							exit(EXIT_FAILURE);
						}
					}

					/* Drop privileges */
					if (setuid(getuid()) == -1)
					{
						perror("setuid");
					}

					channel_hopper(wi, lopt.num_cards, chan_count, main_pid);
					exit(EXIT_FAILURE);
				}
				else if (hopper_pid < 0)
				{
					perror("fork");
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				for (i = 0; i < lopt.num_cards; i++)
				{
#ifdef CONFIG_LIBNL
					wi_set_ht_channel(wi[i], lopt.channel[0], lopt.htval);
#else
					wi_set_channel(wi[i], lopt.channel[0]);
#endif
					lopt.channel[i] = lopt.channel[0];
				}
				lopt.singlechan = 1;
			}
		}
	}

	/* Drop privileges */
	if (setuid(getuid()) == -1)
	{
		perror("setuid");
	}

	// we need to specify the gpsd option when running the ppi option
	if (!(opt.usegpsd) && lopt.ppi) {
		// but only if we don't specify fixed coordinates
		if ((lopt.coordinates[0] == 500 && lopt.coordinates[1] == 500)) {
			printf("--gpsd option must be used with ppi creation option, unless specifying fixed coords. Ignoring this flag.\n");
			sleep(1);
			lopt.ppi = 0;
		}
	}

	if (lopt.tcp_sock_fd == 0) {
		lopt.tcp_sock_fd = start_tcp_server(lopt.ip, lopt.port);  // Start TCP server, get client socket
	}
	// need to set the mactime to zero in the event there is no TSFT in the driver-generated radiotap
	ri.ri_mactime = 0;

	/* check if there is an input file */
	if (opt.s_file != NULL)
	{
		if (!(lopt.f_cap_in = fopen(opt.s_file, "rb")))
		{
			perror("open failed");
			return (EXIT_FAILURE);
		}

		n = sizeof(struct pcap_file_header);

		if (fread(&lopt.pfh_in, 1, (size_t) n, lopt.f_cap_in) != (size_t) n)
		{
			perror("fread(pcap file header) failed");
			return (EXIT_FAILURE);
		}

		if (lopt.pfh_in.magic != TCPDUMP_MAGIC
			&& lopt.pfh_in.magic != TCPDUMP_CIGAM)
		{
			fprintf(stderr,
					"\"%s\" isn't a pcap file (expected "
					"TCPDUMP_MAGIC).\n",
					opt.s_file);
			return (EXIT_FAILURE);
		}

		if (lopt.pfh_in.magic == TCPDUMP_CIGAM) SWAP32(lopt.pfh_in.linktype);

		if (lopt.pfh_in.linktype != LINKTYPE_IEEE802_11
			&& lopt.pfh_in.linktype != LINKTYPE_PRISM_HEADER
			&& lopt.pfh_in.linktype != LINKTYPE_RADIOTAP_HDR
			&& lopt.pfh_in.linktype != LINKTYPE_PPI_HDR)
		{
			fprintf(stderr,
					"Wrong linktype from pcap file header "
					"(expected LINKTYPE_IEEE802_11) -\n"
					"this doesn't look like a regular 802.11 "
					"capture.\n");
			return (EXIT_FAILURE);
		}
	}

	/* open or create the output files */

	if (opt.record_data) {
		if (lopt.dump_prefix == NULL)
		{
			fprintf(stderr, "Output prefix required with -w / --write.\n");
			return (EXIT_FAILURE);
		}
		int ppi = lopt.ppi;
		if (dump_initialize_multi_format(lopt.dump_prefix, ivs_only, ppi, &lopt.tcp_sock_fd))
			return (EXIT_FAILURE);
	}
	struct sigaction action;
	action.sa_flags = 0;
	action.sa_handler = &sighandler;
	sigemptyset(&action.sa_mask);

	if (sigaction(SIGINT, &action, NULL) == -1) perror("sigaction(SIGINT)");
	if (sigaction(SIGSEGV, &action, NULL) == -1) perror("sigaction(SIGSEGV)");
	if (sigaction(SIGTERM, &action, NULL) == -1) perror("sigaction(SIGTERM)");
	if (sigaction(SIGWINCH, &action, NULL) == -1) perror("sigaction(SIGWINCH)");
	if (sigaction(SIGPIPE, &action, NULL) == -1) perror("sigaction(SIGPIPE)");

	/* fill oui struct if ram is greater than 32 MB */
	if (get_ram_size() > MIN_RAM_SIZE_LOAD_OUI_RAM)
	{
		lopt.manufList = load_oui_file();
	}

	/* start the GPS tracker */

	if (opt.usegpsd)
	{
		if (pthread_create(&lopt.gps_tid, NULL, &gps_tracker_thread, NULL) != 0)
		{
			perror("Could not create GPS thread");
			return (EXIT_FAILURE);
		}

		usleep(50000);
		waitpid(-1, NULL, WNOHANG);
	}

	if (!force_legacy_ui)
		use_ncurses_tui = airodump_tui_start(&tui_state);
	else
		use_ncurses_tui = 0;
	(void) atexit(restore_terminal);
	if (!use_ncurses_tui)
	{
		hide_cursor();
		erase_display(2);
	}

	start_time = time(NULL);
	tt1 = time(NULL);
	tt2 = time(NULL);
	gettimeofday(&tv3, NULL);
	gettimeofday(&tv4, NULL);

	lopt.batt = getBatteryString();

	lopt.elapsed_time = (char *) calloc(1, 4);
	if (lopt.elapsed_time == NULL)
	{
		perror("Error allocating memory");
		return (EXIT_FAILURE);
	}
	strlcpy(lopt.elapsed_time, "0 s", 4);

	/* Create start time string for kismet netxml file */
	lopt.airodump_start_time = (char *) calloc(1, 1000 * sizeof(char));
	ALLEGE(lopt.airodump_start_time != NULL);
	strlcpy(lopt.airodump_start_time, ctime(&start_time), 1000);
	lopt.airodump_start_time[strlen(lopt.airodump_start_time) - 1]
		= 0; // remove new line
	lopt.airodump_start_time = (char *) realloc( //-V701
		lopt.airodump_start_time,
		sizeof(char) * (strlen(lopt.airodump_start_time) + 1));
	ALLEGE(lopt.airodump_start_time != NULL);

	// Do not start the interactive mode input thread if running in the
	// background
	if (lopt.background_mode == -1) lopt.background_mode = is_background();

	if (!lopt.background_mode && !use_ncurses_tui
		&& pthread_create(&(lopt.input_tid), NULL, &input_thread, NULL) != 0)
	{
		perror("pthread_create failed");
		return (EXIT_FAILURE);
	}

	while (1)
	{
		int needs_render = 0;

		if (lopt.do_exit)
		{
			break;
		}

		if (hopper_event_pending && use_ncurses_tui && !lopt.background_mode)
		{
			hopper_event_pending = 0;
			ALLEGE(pthread_mutex_lock(&(lopt.mx_print)) == 0);
			render_output();
			ALLEGE(pthread_mutex_unlock(&(lopt.mx_print)) == 0);
		}

		if (time(NULL) - tt1 >= lopt.file_write_interval)
		{
			/* update the text output files */

			tt1 = time(NULL);
			if (opt.output_format_csv)
				dump_write_csv(lopt.ap_1st, lopt.st_1st, lopt.f_encrypt);
			if (opt.output_format_kismet_csv)
				dump_write_kismet_csv(lopt.ap_1st, lopt.st_1st, lopt.f_encrypt);
			if (opt.output_format_kismet_netxml)
				dump_write_kismet_netxml(lopt.ap_1st,
										 lopt.st_1st,
										 lopt.f_encrypt,
										 lopt.airodump_start_time);
		}

		if (time(NULL) - tt2 > 5)
		{
			if (ap_sort_is_live(lopt.sort_by))
			{
				/* sort the APs by power */
				ALLEGE(pthread_mutex_lock(&(lopt.mx_sort)) == 0);
				dump_sort();
				ALLEGE(pthread_mutex_unlock(&(lopt.mx_sort)) == 0);
			}

			/* update the battery state */
			free(lopt.batt);
			lopt.batt = NULL;

			tt2 = time(NULL);
			lopt.batt = getBatteryString();

			/* update elapsed time */

			free(lopt.elapsed_time);
			lopt.elapsed_time = NULL;
			lopt.elapsed_time = getStringTimeFromSec(difftime(tt2, start_time));

			/* flush the output files */

			if (opt.f_cap != NULL) fflush(opt.f_cap);
			if (opt.f_ivs != NULL) fflush(opt.f_ivs);
		}

		gettimeofday(&tv1, NULL);

		cycle_time = 1000000UL * (tv1.tv_sec - tv3.tv_sec)
					 + (tv1.tv_usec - tv3.tv_usec);

		cycle_time2 = 1000000UL * (tv1.tv_sec - tv4.tv_sec)
					  + (tv1.tv_usec - tv4.tv_usec);

		if (lopt.active_scan_sim > 0
			&& cycle_time2 > lopt.active_scan_sim * 1000)
		{
			gettimeofday(&tv4, NULL);
			send_probe_requests(wi, lopt.num_cards);
		}

		if (cycle_time > 500000)
		{
			gettimeofday(&tv3, NULL);
			update_rx_quality();
			if (lopt.s_iface != NULL)
			{
				check_monitor(wi, fd_raw, &fdh, lopt.num_cards);
				if (lopt.singlechan) check_channel(wi, lopt.num_cards);
				if (lopt.singlefreq) check_frequency(wi, lopt.num_cards);
			}
		}

		ri.ri_mactime = 0;
		ri.ri_channel = 0;
		ri.ri_freq = 0;

		if (opt.s_file != NULL)
		{
			static struct timeval prev_tv = {0, 0};

			/* Read one packet */
			n = sizeof(pkh);

			if (fread(&pkh, (size_t) n, 1, lopt.f_cap_in) != 1)
			{
				memset(lopt.message, '\x00', sizeof(lopt.message));
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ Finished reading input file %s.",
						 opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (lopt.pfh_in.magic == TCPDUMP_CIGAM)
			{
				SWAP32(pkh.caplen);
				SWAP32(pkh.len);
			}

			n = caplen = pkh.caplen;

			memset(buffer, 0, sizeof(buffer));
			h80211 = buffer;

			if (n <= 0 || n > (int) sizeof(buffer))
			{
				memset(lopt.message, '\x00', sizeof(lopt.message));
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ Finished reading input file %s.",
						 opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (fread(h80211, (size_t) n, 1, lopt.f_cap_in) != 1)
			{
				memset(lopt.message, '\x00', sizeof(lopt.message));
				snprintf(lopt.message,
						 sizeof(lopt.message),
						 "][ Finished reading input file %s.",
						 opt.s_file);
				opt.s_file = NULL;
				continue;
			}

			if (lopt.pfh_in.linktype == LINKTYPE_PRISM_HEADER)
			{
				if (h80211[7] == 0x40)
				{
					n = 64;
					ri.ri_power = -((int32_t) load32_le(h80211 + 0x33));
					ri.ri_noise = (int32_t) load32_le(h80211 + 0x33 + 12);
					ri.ri_rate = load32_le(h80211 + 0x33 + 24) * 500000;
				}
				else
				{
					n = load32_le(h80211 + 4);
					ri.ri_mactime = load64_le(h80211 + 0x5C - 48);
					ri.ri_channel = load32_le(h80211 + 0x5C - 36);
					ri.ri_power = -((int32_t) load32_le(h80211 + 0x5C));
					ri.ri_noise = (int32_t) load32_le(h80211 + 0x5C + 12);
					ri.ri_rate = load32_le(h80211 + 0x5C + 24) * 500000;
				}

				if (n < 8 || n >= caplen) continue;

				memcpy(tmpbuf, h80211, (size_t) caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, (size_t) caplen);
			}

			if (lopt.pfh_in.linktype == LINKTYPE_RADIOTAP_HDR)
			{
				/* remove the radiotap header */

				n = load16_le(h80211 + 2);

				if (n <= 0 || n >= caplen) continue;

				int got_signal = 0;
				int got_noise = 0;
				struct ieee80211_radiotap_iterator iterator;
				struct ieee80211_radiotap_header * rthdr;

				rthdr = (struct ieee80211_radiotap_header *) h80211;

				if (ieee80211_radiotap_iterator_init(
						&iterator, rthdr, caplen, NULL)
					< 0)
					continue;

				/* go through the radiotap arguments we have been given
				 * by the driver
				 */
				
				while (ieee80211_radiotap_iterator_next(&iterator) >= 0)
				{
					switch (iterator.this_arg_index)
					{
						case IEEE80211_RADIOTAP_TSFT:
							ri.ri_mactime = le64_to_cpu(
								*((uint64_t *) iterator.this_arg));
							break;

						case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
						case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
							if (!got_signal)
							{
								if (*iterator.this_arg < 127)
									ri.ri_power = *iterator.this_arg;
								else
									ri.ri_power = *iterator.this_arg - 255;

								got_signal = 1;
							}
							break;

						case IEEE80211_RADIOTAP_DBM_ANTNOISE:
						case IEEE80211_RADIOTAP_DB_ANTNOISE:
							if (!got_noise)
							{
								if (*iterator.this_arg < 127)
									ri.ri_noise = *iterator.this_arg;
								else
									ri.ri_noise = *iterator.this_arg - 255;

								got_noise = 1;
							}
							break;

						case IEEE80211_RADIOTAP_ANTENNA:
							ri.ri_antenna = *iterator.this_arg;
							break;

						case IEEE80211_RADIOTAP_CHANNEL:
						{
							uint16_t frequency = le16toh(*(uint16_t *) iterator.this_arg);

							ri.ri_freq = frequency;
							ri.ri_channel = getChannelFromFrequency(frequency);
							break;
						}

						case IEEE80211_RADIOTAP_RATE:
							ri.ri_rate = (*iterator.this_arg) * 500000;
							break;
					}
				}

				memcpy(tmpbuf, h80211, (size_t) caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, (size_t) caplen);
			}

			if (lopt.pfh_in.linktype == LINKTYPE_PPI_HDR)
			{
				/* remove the PPI header */

				n = load16_le(h80211 + 2);

				if (n <= 0 || n >= caplen) continue;

				/* for a while Kismet logged broken PPI headers */
				if (n == 24 && load16_le(h80211 + 8) == 2) n = 32;

				if (n <= 0 || n >= caplen) continue; //-V560

				memcpy(tmpbuf, h80211, (size_t) caplen);
				caplen -= n;
				memcpy(h80211, tmpbuf + n, (size_t) caplen);
			}

			read_pkts++;

			if (lopt.relative_time && prev_tv.tv_sec != 0
				&& prev_tv.tv_usec != 0)
			{
				// handle delaying this packet
				struct timeval pkt_tv;
				pkt_tv.tv_sec = pkh.tv_sec;
				pkt_tv.tv_usec = pkh.tv_usec;

				const useconds_t usec_diff
					= (useconds_t) time_diff(&prev_tv, &pkt_tv);

				if (usec_diff > 0) usleep(usec_diff);
			}
			else if (read_pkts % 10 == 0)
				usleep(1);

			// track the packet's timestamp
			prev_tv.tv_sec = pkh.tv_sec;
			prev_tv.tv_usec = pkh.tv_usec;
		}
		else if (lopt.s_iface != NULL)
		{
			/* capture one packet */

			FD_ZERO(&rfds);
			for (i = 0; i < lopt.num_cards; i++)
			{
				FD_SET(fd_raw[i], &rfds); // NOLINT(hicpp-signed-bitwise)
			}
			if (use_ncurses_tui)
			{
				FD_SET(STDIN_FILENO, &rfds);
				if (STDIN_FILENO > fdh) fdh = STDIN_FILENO;
			}

			tv0.tv_sec = lopt.update_s;
			tv0.tv_usec = (lopt.update_s == 0) ? REFRESH_RATE : 0;

			gettimeofday(&tv1, NULL);

			if (select(fdh + 1, &rfds, NULL, NULL, &tv0) < 0)
			{
				if (errno == EINTR)
				{
					gettimeofday(&tv2, NULL);

					time_slept += 1000000UL * (tv2.tv_sec - tv1.tv_sec)
								  + (tv2.tv_usec - tv1.tv_usec);

					continue;
				}
				perror("select failed");

				/* Restore terminal */
				restore_terminal();

				return (EXIT_FAILURE);
			}
		}
		else
			usleep(1);

		gettimeofday(&tv2, NULL);

		time_slept += 1000000UL * (tv2.tv_sec - tv1.tv_sec)
					  + (tv2.tv_usec - tv1.tv_usec);

		if (use_ncurses_tui)
		{
			int keycode;

			if (tui_resize_pending)
			{
				tui_state.resize_pending = 1;
				tui_resize_pending = 0;
				needs_render = 1;
			}

			while ((keycode = airodump_tui_getch(&tui_state)) != -1)
			{
				if (handle_keycode(keycode)) needs_render = 1;
			}
		}

		if (needs_render && !lopt.background_mode)
		{
			ALLEGE(pthread_mutex_lock(&(lopt.mx_print)) == 0);
			render_output();
			ALLEGE(pthread_mutex_unlock(&(lopt.mx_print)) == 0);
		}

		if (time_slept > REFRESH_RATE && time_slept > lopt.update_s * 1000000)
		{
			time_slept = 0;

			update_dataps();

			/* update the window size */

			if (ioctl(0, TIOCGWINSZ, &(lopt.ws)) < 0)
			{
				lopt.ws.ws_row = 25;
				lopt.ws.ws_col = 80;
			}

			/* display the list of access points we have */

			if (!lopt.do_pause && !lopt.background_mode)
			{
				ALLEGE(pthread_mutex_lock(&(lopt.mx_print)) == 0);

				render_output();

				ALLEGE(pthread_mutex_unlock(&(lopt.mx_print)) == 0);
			}
			continue;
		}

		if (opt.s_file == NULL && lopt.s_iface != NULL)
		{
			for (i = 0; i < lopt.num_cards; i++)
			{
				if (FD_ISSET(fd_raw[i], &rfds)) // NOLINT(hicpp-signed-bitwise)
				{

					memset(buffer, 0, sizeof(buffer));
					h80211 = buffer;
					if ((caplen = wi_read(
							 wi[i], NULL, NULL, h80211, sizeof(buffer), &ri))
						== -1)
					{
						wi_read_failed++;
						if (wi_read_failed > 1)
						{
							lopt.do_exit = 1;
							break;
						}
						memset(lopt.message, '\x00', sizeof(lopt.message));
						snprintf(lopt.message,
								 sizeof(lopt.message),
								 "][ interface %s down ",
								 wi_get_ifname(wi[i]));

						// reopen in monitor mode

						strlcpy(ifnam, wi_get_ifname(wi[i]), sizeof(ifnam));

						wi_close(wi[i]);
						wi[i] = wi_open(ifnam);
						if (!wi[i])
						{
							printf("Can't reopen %s\n", ifnam);

							/* Restore terminal */
							restore_terminal();

							exit(EXIT_FAILURE);
						}

						fd_raw[i] = wi_fd(wi[i]);
						if (fd_raw[i] > fdh) fdh = fd_raw[i];

						break;
					}

					read_pkts++;

					wi_read_failed = 0;
					dump_add_packet(h80211, caplen, &ri, i);
				}
			}
		}
		else if (opt.s_file != NULL)
		{
			dump_add_packet(h80211, caplen, &ri, i);
		}

		if (quitting && time(NULL) - quitting_event_ts > 3)
		{
			quitting_event_ts = 0;
			quitting = 0;
			snprintf(lopt.message, sizeof(lopt.message), "]");
		}

		if (deauth_launching && time(NULL) - deauth_event_ts > 3)
		{
			deauth_event_ts = 0;
			deauth_launching = 0;
			snprintf(lopt.message, sizeof(lopt.message), "]");
		}
	}

	if (lopt.tcp_sock_fd > 0) {
        close(lopt.tcp_sock_fd);  // Close socket after capture loop exits
    }

	if (lopt.batt) free(lopt.batt);

	if (lopt.elapsed_time) free(lopt.elapsed_time);

	if (lopt.own_channels) free(lopt.own_channels);

	if (lopt.f_essid) free(lopt.f_essid);

	if (opt.prefix) free(opt.prefix);

	if (opt.f_cap_name) free(opt.f_cap_name);

	if (lopt.keyout) free(lopt.keyout);

#ifdef HAVE_PCRE
	if (lopt.f_essid_regex) pcre_free(lopt.f_essid_regex);
#endif

	for (i = 0; i < lopt.num_cards; i++) wi_close(wi[i]);

	if (opt.record_data)
	{
		if (opt.output_format_csv)
			dump_write_csv(lopt.ap_1st, lopt.st_1st, lopt.f_encrypt);
		if (opt.output_format_kismet_csv)
			dump_write_kismet_csv(lopt.ap_1st, lopt.st_1st, lopt.f_encrypt);
		if (opt.output_format_kismet_netxml)
			dump_write_kismet_netxml(lopt.ap_1st,
									 lopt.st_1st,
									 lopt.f_encrypt,
									 lopt.airodump_start_time);

		if (opt.output_format_csv && opt.f_txt != NULL) fclose(opt.f_txt);
		if (opt.output_format_kismet_csv && opt.f_kis != NULL)
			fclose(opt.f_kis);
		if (opt.output_format_kismet_netxml && opt.f_kis_xml != NULL)
		{
			fclose(opt.f_kis_xml);
			free(lopt.airodump_start_time);
		}
		if (opt.f_gps != NULL) fclose(opt.f_gps);
		if (opt.output_format_pcap && opt.f_cap != NULL) fclose(opt.f_cap);
		if (opt.f_ivs != NULL) fclose(opt.f_ivs);
		if (opt.f_logcsv != NULL) fclose(opt.f_logcsv);
		if (opt.f_probes != NULL) fclose(opt.f_probes);
		free_probe_log_entries();
	}

	if (!lopt.save_gps)
	{
		snprintf((char *) buffer, 4096, "%s-%02d.gps", argv[2], opt.f_index);
		unlink((char *) buffer);
	}

	if (opt.usegpsd)
	{
		void * retval = NULL;
		pthread_join(lopt.gps_tid, &retval);
		if (retval != NULL) free(retval);
	}

	if (!lopt.background_mode && !use_ncurses_tui)
	{
		pthread_join(lopt.input_tid, NULL);
	}

	ap_cur = lopt.ap_1st;

	while (ap_cur != NULL)
	{
		// Clean content of ap_cur list (first element: lopt.ap_1st)
		uniqueiv_wipe(ap_cur->uiv_root);

		list_tail_free(&(ap_cur->packets));

		if (lopt.manufList) free(ap_cur->manuf);

		if (lopt.detect_anomaly) data_wipe(ap_cur->data_root);

		ap_cur = ap_cur->next;
	}

	ap_cur = lopt.ap_1st;

	while (ap_cur != NULL)
	{
		// Freeing AP List
		ap_next = ap_cur->next;
		free(ap_cur);
		ap_cur = ap_next;
	}

	st_cur = lopt.st_1st;

	while (st_cur != NULL)
	{
		st_next = st_cur->next;
		if (lopt.manufList) free(st_cur->manuf);
		free(st_cur);
		st_cur = st_next;
	}

	na_cur = lopt.na_1st;

	while (na_cur != NULL)
	{
		na_next = na_cur->next;
		free(na_cur);
		na_cur = na_next;
	}

	if (lopt.manufList)
	{
		oui_cur = lopt.manufList;
		while (oui_cur != NULL)
		{
			oui_next = oui_cur->next;
			free(oui_cur);
			oui_cur = oui_next;
		}
	}

	restore_terminal();

	return (EXIT_SUCCESS);
}
