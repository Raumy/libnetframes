/*
 * read_pcap_file.vala
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
    read_pcap_file.vala ../lib/libnetframes.vapi -o read_pcap_file.exe	
*/

// Sample test program

using NetFrames;

void main (string[] args) {
	Capture test = new Capture(args[1]);
	Hosts h = test.hosts;

	stdout.printf ("hosts list\n");
	h.display();
	stdout.printf ("\n");

	stdout.printf ("connections list\n");
	test.connections.display();
	stdout.printf ("\n");
	test.frames.display();

	Frame f = test.frames.get_at(5);
	f.display();
	stdout.printf ("dissect : <%s>\n", f.dissect);	
}