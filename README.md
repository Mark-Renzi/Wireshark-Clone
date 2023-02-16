# Wireshark-Clone
A linux terminal-based clone of wireshark to analyze network packets. Currently configured to analyze packets saved to a PCAP file, sample files provided.s

Analyzing network packets on your network may be against usepolicies defined by your network administrators.
I AM NOT RESPONSIBLE FOR ANY USE OF THIS PROGRAM. CREATION EXISTS FOR EDUCATIONAL PURPOSES ONLY.

Compile wireview with "make all", "make", or "make clean".

Run with "./wireview {numPackets} {fileName}".

./wireview {numPackets} {fileName}

{numPackets}:
-1 for all packets in file (if using network card as source, -1 will loop infinitely until Ctrl+C)

{fileName}:
name of file to open with extension
