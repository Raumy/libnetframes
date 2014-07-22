/*
 * edit_pcap_file.vala
 *
 * Copyright 2013-2014 Cyriac REMY <raum@no-log.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */
 /*
 * Read a pcap file and show some informations
 */

/*
vala --disable-warnings  -X -w  --target-glib=2.32 \
    --pkg libpcap --pkg gee-0.8  --pkg gio-2.0 \
    -X -lwpcap -X ../lib/libnetframes.dll \
    -X -I../lib -X -I/opt/include \
    edit_pcap_file.vala ../lib/libnetframes.vapi -o edit_pcap_file.exe	
*/

// Sample test program

using NetFrames;

void main (string[] args) {
	Capture test = new Capture(args[1]);
	InetAddress host_to_del = new InetAddress.from_string(args[2]);

	Hosts h = test.hosts;

	stdout.printf ("hosts list\n");
	h.display();
	stdout.printf ("count connections : %d\n", test.connections.size);
	stdout.printf ("\n");

	Connection c = test.connections.search_connection_by_host(host_to_del);
	stdout.printf ("number of sessions in connection : %d\n", c.sessions.size);

	stdout.printf ("delete %s\n", args[2]);	
	test.delete_host(host_to_del);
	h.display();
	stdout.printf ("count connections : %d\n", test.connections.size);
}