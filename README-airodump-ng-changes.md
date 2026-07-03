# airodump-ng UI and Workflow Changes

This document summarizes the behavior changes made in this workspace.

## Hotkeys

- `d`: launch `log_sta` with a double-press confirmation.
- `r`: resume channel hopping after parking on a selected AP channel.
- `b`: switch the active band.
- `R`: toggle realtime sorting.

## `log_sta` launch flow

- Runs `log_sta -0 1 -a <AP_MAC> -c <STA_MAC> <wlan_if>`.
- Stops channel hopping before the command runs.
- Redirects the child process output into the TUI message history instead of the terminal.
- Waits for the command to finish before returning.
- Leaves the capture parked on the selected AP channel after completion.

## Band switching

- `b` cycles the active band preset.
- The current band is shown in the top status/header line.
- The current implementation uses the built-in band tables already present in `airodump-ng`.
- If the adapter cannot support a band cleanly, the next step is to make the switch capability-aware and skip unsupported bands.

## Messages pane

- Message text wraps instead of running off the edge.
- The messages pane follows the latest message unless the user scrolls up.
- The latest PMKID and WPA handshake messages are recorded immediately when they are detected.
- The message history now updates as soon as `log_sta` output or capture events occur, rather than waiting for another redraw-triggering event.

## UI layout

- The AP pane now sizes itself to the width of its content.
- The messages pane uses the remaining horizontal space.
- The AP table headers were realigned with the data columns.

## Build notes

- The Debian build target has been used to verify the changes.
- The local macOS build in this workspace is missing `pcre.h`, so Debian is the reliable verification path here.
