/*
 * hosts.vala
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
 * Classe simple contenant l'ensemble des hôtes lus à partir du fichier
 * au format PCAP standard. Il s'agit d'adresse Internet
 *
 */

using Gee;

namespace NetFrames {

public class Hosts : ArrayList<InetAddress> {
	internal Hosts.Frames(Frames frames) {
		foreach (Frame f in frames)
			add_frame(f);
	}
	internal Hosts.Frame(Frame f) {
		add_frame(f);
	}

	internal void add_frame(Frame f) {
		if (! contains(f.src))
			add(f.src);

		if (! contains(f.dst))
			add(f.dst);
	}

	public new bool contains(InetAddress addr) {
		for (int index = 0; index < size; index++) {
			if (this[index].equal(addr)) {
				return true;
			}
		}
		return false;
	}

	public void display() {
		foreach (InetAddress addr in this) {
			stdout.printf ("address: %s\n", addr.to_string());
		}
	}

	internal void delete_host(InetAddress host) {
		foreach (InetAddress h in this)
			if (host.equal(h)) {
				remove(h);
				return;
			}
	}
}
}