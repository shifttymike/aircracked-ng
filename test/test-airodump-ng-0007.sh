#!/bin/sh
# Airodump-ng: TUI smoke test

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present screen

# Check for interfering processes
airmon_ng_check

# Cleanup
finish() {
	screen_cleanup
	[ -n "${TEMP_FILE}" ] && [ -f "${TEMP_FILE}-01.csv" ] && rm -f ${TEMP_FILE}*
	cleanup
}

trap  finish INT QUIT SEGV PIPE ALRM TERM EXIT

# Load mac80211_hwsim
load_module 1

# Check there are two radios
check_radios_present 1

# Get interfaces names
get_hwsim_interface_name 1
WI_IFACE=${IFACE}

CHANNEL=9

# Put interface in monitor mode
set_monitor_mode ${WI_IFACE}
[ $? -eq 1 ] && exit 1
set_interface_channel ${WI_IFACE} ${CHANNEL}
[ $? -eq 1 ] && exit 1

TEMP_FILE=$(mktemp -u)
screen -AmdS capture \
	timeout 6 \
		"${abs_builddir}/../airodump-ng" \
			${WI_IFACE} \
			-c  10 \
			-w ${TEMP_FILE}

# Give ncurses time to initialize, then send a few keys.
sleep 1
screen -S capture -X stuff "$(printf '\033[B\033[6~\033[5~qq')"

# Wait for the session to exit and confirm it cleaned up.
sleep 2
if screen -ls 2>/dev/null | ${GREP} -q '\.capture'; then
	echo "Airodump-ng TUI session did not exit cleanly"
	exit 1
fi

if [ ! -f "${TEMP_FILE}-01.csv" ]; then
	echo "TUI smoke test did not produce CSV output"
	exit 1
fi

exit 0
