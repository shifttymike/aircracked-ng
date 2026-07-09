# airodump-ng UI and Workflow Changes

This document summarizes the behavior changes made in this workspace.

## Hotkeys

- `d`: launch `deauth` with a double-press confirmation.
- `r`: resume channel hopping after parking on a selected AP channel.
- `b` / `B`: switch the active band next / previous.
- `v`: show active-band channel availability, with unavailable or driver-refused targets highlighted red.
- `w`: write the buffered WPA/PMKID records to an IVS2 snapshot file.
- `t`: tune all capture interfaces to a channel and stop hopping.
- `l`: lock all capture interfaces to the selected AP's channel.
- `s` / `S`: cycle the sort field in the active pane next / previous.
- `R`: toggle realtime sorting.
- `M`: toggle mouse capture.
- `c`: clear the selected AP filter.
- `?` / `F1`: show or close the TUI help overlay.

## Header

- The top header shows the current channel and effective frequency in MHz for each capture card.
- Channel/frequency fields are fixed-width so the rest of the header does not shift when channel numbers change.
- The header shows the active band preset.
- The header shows the active interface's actual kernel-reported regulatory domain from `iw reg get`, not the last requested value.
- Hopper warnings are surfaced when the driver refuses a channel or frequency, including the refused target, total rejected count, and current regdom.
- `v` opens a channel availability overlay for the active band; white entries are usable by the hopper, red entries are unavailable from the driver/regdom list or were refused during this run.
- `w` writes the currently buffered WPA/PMKID material to an IVS2 file for later cracking.
- WPA3 transition APs are labeled `WPA2/3` in the security column, and the auth column shows `PSK+SAE` instead of looking identical to pure WPA3.

## `deauth` launch flow

- Runs `deauth -0 1 -a <AP_MAC> -c <STA_MAC> <wlan_if>`.
- Stops channel hopping before the command runs.
- Redirects the child process output into the TUI message history instead of the terminal.
- Waits for the command to finish before returning.
- Leaves the capture parked on the selected AP channel after completion.

## Band switching

- `b` cycles the active band preset forward: 2.4 GHz -> 5 GHz -> 6 GHz -> 2.4 GHz.
- `B` cycles the active band preset backward.
- Band switching skips bands that are not supported by the current adapter set.
- `v` shows the channel list for the current band and highlights unavailable or driver-refused targets.
- The current band is shown in the top status/header line.
- The current implementation uses the built-in band tables already present in `airodump-ng`.

## Channel controls

- `t` opens a channel prompt, validates the channel against the active band, parks all capture interfaces there, and stops hopping.
- `l` locks all capture interfaces to the currently selected AP channel, if one is selected.
- If 6 GHz frequencies are refused by the driver, use `b` / `B` to switch to another band. The current regdom remains visible in the header for context.

## Messages pane

- Message text wraps instead of running off the edge.
- The messages pane follows the latest message unless the user scrolls up.
- The latest PMKID and WPA handshake messages are recorded immediately when they are detected.
- The message history now updates as soon as `deauth` output or capture events occur, rather than waiting for another redraw-triggering event.

## UI layout

- The AP pane now sizes itself to the width of its content.
- The messages pane uses the remaining horizontal space.
- The AP table headers were realigned with the data columns.
- The AP and station tables include a `Band` column so historical rows remain clear after band changes.
- The station table includes an `LA` column for locally administered station MAC addresses.

## Sorting

- AP and station panes can be sorted from the keyboard with `s` / `S`.
- AP and station table headers can be sorted with a mouse press.
- Mouse sorting triggers on button press instead of release, so holding the click does not cancel the sort.
- The AP `STAs` column is sortable and uses the BSS load station count.
- The AP `STAs` column now shows `visible/advertised`, where `visible` is the number of stations seen within the Berlin window and `advertised` comes from BSS Load.
- AP `ESSID` sorting is stable across refreshes and keeps hidden SSIDs grouped consistently.
- Station sorting includes the `LA` column.

## Build notes

- The Debian build target has been used to verify the changes.
- The local macOS build in this workspace is missing `pcre.h`, so Debian is the reliable verification path here.
