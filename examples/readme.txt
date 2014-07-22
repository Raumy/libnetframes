How to compile these two samples for Windows :

vala --disable-warnings  -X -w  --target-glib=2.32 \
    --pkg libpcap --pkg gee-0.8  --pkg gio-2.0 \
    -X -lwpcap -X ../lib/libnetframes.dll \
    -X -I../lib -X -I/opt/include \
    edit_pcap_file.vala ../lib/libnetframes.vapi -o edit_pcap_file.exe

vala --disable-warnings  -X -w  --target-glib=2.32 \
    --pkg libpcap --pkg gee-0.8  --pkg gio-2.0 \
    -X -lwpcap -X ../lib/libnetframes.dll \
    -X -I../lib -X -I/opt/include \
    read_pcap_file.vala ../lib/libnetframes.vapi -o read_pcap_file.exe	

For linux, you should replace wpcap by pcap and remove ".exe" extension ;)

