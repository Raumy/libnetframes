/*
 * connections.vala
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
 * Regroupement de classes permettant la création et la gestion
 * d'une structure de "connexions".
 */

using Gee;

namespace NetFrames {

/*
 * Une connexion entre deux hôtes existe à partir du moment où il
 * existe au moins une session entre les deux hôtes.
 * Une connexion regroupe aussi l'ensemble des sessions entre deux
 * hôtes.
 */

public const int DEFAULT_LAN_LATENCY = 1000; // 1 ms = 1 000 µs
public const int DEFAULT_WAN_LATENCY = 15000; // 15 ms = 10 000 µs

//	public int latency = 10000; // 10 ms = 10 000 µs
	public int latency = 1000; // 10 ms = 10 000 µs  LAN LATENCY

public class Connection : Object {
	/* Connexion entre l'hôte host_a et l'hôte host_b */
	public InetAddress host_a = null;
	public InetAddress host_b = null;

	public uint32 total_size { get { return sessions.total_size; } }
	public uint32 size_from_host_a { get { return sessions.size_from_host_a; } }
	public uint32 size_from_host_b { get { return sessions.size_from_host_b; } }

	/* Ensemble de sessions dans une connexion */
	public Sessions sessions = new Sessions();

	/* Latence en microsecond */
	public int32 latency = DEFAULT_LAN_LATENCY;
	public int32 suggested_latency = DEFAULT_LAN_LATENCY;

	public Connection(InetAddress a, InetAddress b) {
		host_a = a;
		host_b = b;
	}

	~Connection() {
		foreach (Session s in sessions)
			s.frames.clear();

		sessions.clear();
	}

	public int64 calcul_suggested_latency(InetAddress capture_from) {
		int64 min = -1;
		int64 max = 0;
		int64 connection_latency = -1;

		foreach (Session s1 in sessions) {
			min = -1;
			max = 0;

			if (s1.flow_informations == null)
				continue;	

		    foreach (uint32 key in s1.flow_informations.assoc_seq_acknowledged.keys) {
		        Frame f_ack = s1.get_frame_by_num(key);

				if (! f_ack.src.equal(capture_from)) {
					Frame f_seq = s1.get_frame_by_num(s1.flow_informations.assoc_seq_acknowledged[key]);

					DateTime dt_seq =  new DateTime.from_timeval_utc (f_seq.time);
					DateTime dt_ack =  new DateTime.from_timeval_utc (f_ack.time);
					int64 t_stamp = dt_ack.difference(dt_seq);

					if ((min == -1) || (t_stamp < min))
						min = t_stamp;

					if (t_stamp > max) max = t_stamp;
			    }

			}
			s1.display();
			stdout.printf ("current : %d\n", (int) min);;

			if ((connection_latency == -1) || (connection_latency > min))
				connection_latency = min;
		}

		if (connection_latency != -1) {
			connection_latency = (int64) (connection_latency / 2);
		}

		suggested_latency = (int32) (connection_latency);

		return suggested_latency;
	}

	public int total_frames() {
		int total = 0;

		foreach (Session s in sessions)
				total += s.frames.size;

		return total;
	}

	public void delete_session(Session s) {
		Session to_search = sessions.search_session(s);

		if (to_search == null)
			return;

		to_search.frames.clear();
		sessions.remove(to_search);
	}

	public bool is_equal(Connection c) {
		return  ((c.host_a.equal(host_a) && c.host_b.equal(host_b)) ||
		    (c.host_a.equal(host_b)) && c.host_b.equal(host_a));
	}

	public bool has_host(InetAddress host) {
		return (host.equal(host_a) || host.equal(host_b));
	}

	public void display() {
		stdout.printf ("%s\n", to_string());
		sessions.display();
	}

	public string to_string() {
		return "%s  <===>  %s (nb sessions : %d)". printf(host_a.to_string(), host_b.to_string(), sessions.size);
	}
}

public class Connections : ArrayList<Connection> {
	public int total_size = 0;
	public int size_from_host_a = 0;
	public int size_from_host_b = 0;

	public Connection search_connection(Connection to_search) {
		foreach (Connection c in this) {
			if (c.is_equal(to_search))
				return c;
		}
		return (Connection) null;
	}

	public Session search_session_by_host(Connections connections, SocketInfos host) {
		Session s = null;

		foreach (Connection c in connections) {
			foreach (Session sb in c.sessions) {
				if (sb.host_a.is_equals(host) || sb.host_b.is_equals(host))
					return sb;
			}
		}

		return (Session) null;
	}

	public Connection? search_connection_by_host(InetAddress host) {
		foreach (Connection c in this)
			if (c.has_host(host)) return c;

		return (Connection) null;
	}

	internal void detect_client_server_for_sessions() {
		foreach (Connection c in this)
			foreach (Session s in c.sessions)
				s.detect_client_server();
	}

	internal Connection add_connection(Connection c) {
		Connection found = search_connection(c);

		if (found == null) {
			add(c);
			return c;
		}

		//total_size =
		return found;
	}

	internal void delete_by_host(InetAddress host) {
		Connection connection = null;
		int i = 0;

		while (i < size) {
			connection = this[i];
			if (connection.has_host(host)) {
				connection.sessions.clear();
				remove(connection);
				//free(connection);
			} else
				i++;
		}
	}

	internal void delete_connection(Connection c) {
		Connection connection = search_connection(c);

		if (connection != null) {
				connection.sessions.clear();
				remove(connection);
		}
	}

	internal void delete_session(Session s) {
		Connection connection = search_connection(new Connection(s.host_a.addr, s.host_b.addr));

		if (connection == null) {
			stdout.printf ("Erreur : tentative de suppression d'une session dans une connexion inexistante\n");
			return;
		}

		connection.delete_session(s);

		if (connection.sessions.size == 0)
			remove(connection);
	}


	public InetAddress get_host_by_max_peers(Hosts hosts) {
		InetAddress ref_host = null;
		int count = 0;
		int tmp_count = 0;

		foreach (InetAddress host in hosts) {
			tmp_count = 0;

			foreach (Connection c in this)
				if (c.has_host(host)) tmp_count++;


			if (tmp_count > count) {
				ref_host = host;
				count = tmp_count;
			}

		}
		return ref_host;
	}


	public void display() {
		foreach (Connection c in this)
			c.display();
	}
}

	public string latency_to_string(int32 latency) {
		if (latency >= 1000) {
			double to_ms = ((double) latency / 1000);

			char[] buf = new char[double.DTOSTR_BUF_SIZE];
			return to_ms.format (buf, "%g") + "ms";
		}

		return latency.to_string() + "µs";
	}


}
