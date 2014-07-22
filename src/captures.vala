/*
 * captures.vala
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
 * Regroupement de classes permettant la création d'une structure
 * de type capture à partir d'un fichier au format PCAP standard.
 */

//              stdout.printf ("::: %s - %s :: %d ::: \n", GLib.Log.FILE, GLib.Log.METHOD, GLib.Log.LINE);


using Gee;

namespace NetFrames {
/*
 * Une capture contient
 *     l'ensemble des trames du fichier lu
 *     l'ensemble des hôtes extrait de la capture
 *     l'ensemble des connexions entre hôtes
 *			remarque : une connexion est composée de l'ensemble des sessions et
 			les sessions sont composées des trames
 *
 * La classe capture permet la création de la structure capture à partir
 * d'un ensemble de trames lu à partir d'un fichier au format PCAP standard
 * et l'écriture de l'ensemble des trames au format PCAP standard.
 */

public class GroupedFrames {
	public Frame from_frame = null;
	public Frames to_frames = new Frames();
}

public class Capture : Object {
	string _pcap_filename = "";
	public string filename { get { return _pcap_filename; } }
	public InetAddress capture_from = null;

	public PCapHeader pcap_header = null;

	private Frames _frames = new Frames();
	public Frames frames { get { return _frames; } }

	Hosts _hosts = new Hosts();
	public Hosts hosts { get { return _hosts; } }

	Connections _connections = new Connections();
	public Connections connections { get { return _connections; } }

	public bool compatibility_mode = false;

	ArrayList<GroupedFrames> grouped_frames = null;

	 public  Frame get_first_frame_captured() {
	 	Frame f = _frames.get_at(0);
		return  f;
	}

	/*
		Constructors
	*/
	 ~Capture() {
		_frames.clear();
		_hosts.clear();
		_connections.clear();
	}
/*
	public Capture(string filename, bool shark_decode = true,  bool compat = false) {
		_pcap_filename = filename;
		_frames.load_pcap_file(filename, this, compat);
 		if (shark_decode)
			_frames.tshark_decode(filename, this);
	}
*/
	public Capture.Null() {

	}

	public Capture(string filename, InetAddress? capture_from = null, bool shark_decode = true) {
		_pcap_filename = filename;
		_frames.load_pcap_file(filename, this);

 		if (shark_decode)
			_frames.tshark_decode(filename, this);

		build_structures();
		this.capture_from = capture_from;
		_connections.detect_client_server_for_sessions();

		//build_grouped_frames(s1, new InetAddress.from_string("10.104.221.194"));
	}

	public void set_captured_host(InetAddress host) {
		int32 suggest_latency = 0;

		capture_from = host;
		foreach (Connection c in _connections) {
			suggest_latency = (int32) c.calcul_suggested_latency(capture_from);
			if (suggest_latency == -1)  continue;

			if (suggest_latency > 1000)
				c.latency = suggest_latency - suggest_latency % 100;
			else
				c.latency = suggest_latency ;
		}
	}

	public void save_pcap(string uri) {
		_frames.save_pcap(uri);
	}

	/*
		Internal functions
	*/
	internal void add_host(Frame? f) {
		if (f == null) return;
		_hosts.add_frame(f);
	}

	internal Connection add_connection(Connection c) {
		return _connections.add_connection(c);
	}


	public void build_structures() {
		int32 suggest_latency = 0;

		foreach (Frame f in frames) {
			add_host(f);

			// On ajoute une connexion, si elle existe déjà on la récupère
			// et on ajoute la trame à la connexion
			Connection c = add_connection(new Connection(f.src, f.dst));

			c.sessions.add_frame(f);

		}


		foreach (Connection c in _connections) {
			foreach (Session s in c.sessions) {
				s.build_flow_informations();
			}

			if (capture_from != null) {
				suggest_latency = (int32) c.calcul_suggested_latency(capture_from);
				if (suggest_latency != -1) {
					c.latency = suggest_latency;
				}
			}
		}
	}

	void clean_orphans_hosts(InetAddress? host) {
		int i = 0;
		InetAddress ip = null;

		while (i < hosts.size) {
			ip = hosts[i];

			if (connections.search_connection_by_host(ip) == null) {
				delete_host(ip);
			} else
				i++;
		}
	}

	/*
		Public functions (delete single host / single connection / single sessions)
	*/
	public void delete_connection (Connection c) {
		_connections.delete_connection(c);
		_frames.delete_connection(c);
		clean_orphans_hosts(null);
	}

	public void delete_host(InetAddress host) {
		_connections.delete_by_host(host);
		_hosts.delete_host(host);
		_frames.delete_host(host);
		clean_orphans_hosts(host);
	}

	public void delete_session(Session s) {
		_connections.delete_session(s);
		_frames.delete_session(s);
		clean_orphans_hosts(null);
	}

	/*
		Public functions for debugging purpose
	*/

	public void display_host_frames(InetAddress host) {
		foreach (Frame frame in frames) {
			if (host.equal(frame.src) || host.equal(frame.dst))
				frame.display();
		}
	}

	public void display_connection_frames(InetAddress host) {
		foreach (Connection c in connections) {
			if (c.has_host(host)) {
				c.sessions.display();
				return;
			}
		}
	}

	public void display() {
		stdout.printf ("nombre de trames : %d\n", frames.size);
		_frames.display();
	}
/*
	foreach (GroupedFrames gp in agp) {
		stdout.printf ("from %s\n", frame_to_string(s1, gp.from_frame));
		foreach (Frame f in gp.to_frames) {
			stdout.printf ("to %s\n", frame_to_string(s1, f));
		}
	}
*/
}

}
