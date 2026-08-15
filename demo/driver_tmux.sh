#!/usr/bin/env bash
# Record the sipmon demo with asciinema, driven through tmux send-keys.
# Uses a dedicated tmux server (-L demo_rec) so the window size is exactly
# 150x44 regardless of any attached terminal.
set -u

WS=/home/rzl/workspace/rs/sipmon
CAST=$WS/demo/demo.cast
BIN=$WS/target/debug/sipmon
S=demo_rec
T="tmux -L demo_rec -f /dev/null"

# reset any stale session
$T kill-session -t $S 2>/dev/null
rm -f "$CAST"

$T new-session -d -x 150 -y 44 -s $S
sleep 0.5

send() { $T send-keys -t $S "$1" Enter; sleep "$2"; }
key()  { $T send-keys -t $S "$1"; sleep "$2"; }

send 'export PATH="$HOME/.cargo/bin:$PATH"' 0.5
send 'cd '"$WS" 0.5
send 'clear' 0.6

# start asciinema in the tmux pane
$T send-keys -t $S 'asciinema rec -y --title "sipmon demo" '"$CAST" Enter
sleep 2

send 'ls' 0.8
send "$BIN --help" 1.5
send 'python3 tools/gen_load.py -o /tmp/demo_load.pcap --calls 16 --talk 45 --spread 90' 12
send 'ls -lh /tmp/demo_load.pcap' 0.8
send "$BIN /tmp/demo_load.pcap --no-tui" 3

# TUI replay of the load
send "$BIN file -r /tmp/demo_load.pcap --rate 4" 4
key 'f' 0.9
key 'f' 0.9
key 'f' 0.9
key 'f' 0.9
key 'f' 0.9
key 'f' 0.9
key 'f' 0.9
key 'Down' 0.6
key 'Down' 0.6
key 'Up' 0.6
key 'Enter' 1.2
key 'Tab' 1.2
sleep 5
key 'Tab' 0.9
key '1' 0.9
key '4' 1.0
key '5' 1.0
key '6' 1.0
key '7' 1.2
key 's' 1.0
key 'w' 1.0
key 'Enter' 1.2
key 'Esc' 0.8
key '1' 0.9
key 'q' 2
send 'echo SHELL_BACK_OFFLINE' 0.8

# live demo with sipbot
send 'sipbot wait -a 127.0.0.1:25060 -d 127.0.0.1 --echo >/tmp/demo/callee.log 2>&1 & echo callee_up' 1
send '(sleep 2; sipbot call -t sip:callee@127.0.0.1:25060 --hangup 10 >/tmp/demo/c1.log 2>&1) & echo call1_scheduled' 1
send '(sleep 18; sipbot call -t sip:callee@127.0.0.1:25060 --hangup 14 >/tmp/demo/c2.log 2>&1) & echo call2_scheduled' 1
send "sudo -n $BIN live -i lo -f udp" 4
key 'Enter' 1.0
key 'Tab' 1.0
sleep 6
key '1' 1.0
key '4' 1.0
sleep 2
key '5' 1.0
key '6' 1.0
key '7' 1.0
key 'x' 1.0
key 'q' 2
send 'echo SHELL_BACK_LIVE' 0.8

send 'sudo -n pkill -x sipbot; echo cleaned' 1
send 'exit' 1
sleep 2
$T kill-session -t $S 2>/dev/null
echo "recording done: $CAST"
