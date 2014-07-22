/*
 * sessions.vala
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
 * Regroupement de classes permettant la création et la manipulation
 * de sessions.
 *
 */

using Gee;

/*
 * Une session est une session au sens qu'il existe une session
 * TCP ou UDP entre deux hôtes avec des ports identifiés.
 */
 namespace NetFrames {

public class SocketInfos : Object {
	public InetAddress addr;
	public uint16 port;

	public SocketInfos(InetAddress a, uint16 p) {
		addr = a;
		port = p;
	}

	~SocketInfos() {
		addr = null;
	}

	public bool is_equals(SocketInfos s) {
		return (addr.equal(s.addr) && (port == s.port));
	}

	public string to_string() {
		return "%s:%d".printf(addr.to_string(), port);
	}
}

public class Session : Object {
	public enum SESSION_TYPE {
		UNKNOWN,
		TCP,
		UDP
	}

	public SocketInfos host_a = null;
	public SocketInfos host_b = null;
	public ArrayList<Frame> frames = new ArrayList<Frame>();
	/*
	public SocketInfos host_syn = null;
	public SocketInfos host_syn_ack = null;
	*/

	public SocketInfos first_frame_host = null;
	public SocketInfos second_frame_host = null;



	public uint32 total_size = 0;
	public uint32 size_from_host_a = 0;
	public uint32 size_from_host_b = 0;

   	public uint32 seq_syn = 0;
   	public uint32 seq_syn_ack = 0;

   	public SESSION_TYPE session_type = SESSION_TYPE.UNKNOWN;

	public FlowInformations flow_informations = null;

	public Session(SocketInfos a, SocketInfos b) {
		host_a = a;
		host_b = b;
	}

	public Session.from_addr(InetAddress a, uint16 port_a,
							InetAddress b, uint16 port_b) {
		host_a = new SocketInfos(a, port_a);
		host_b = new SocketInfos(b, port_b);
	}

	public bool is_equals(Session s) {
		return (host_a.is_equals(s.host_a) && host_b.is_equals(s.host_b));
	}

	public bool in_session(Session s) {
		// stdout.printf ("%s / %s\n", host_a.to_string(), host_b.to_string());
		return ((host_a.is_equals(s.host_a) && host_b.is_equals(s.host_b)) ||
				(host_b.is_equals(s.host_a) && host_a.is_equals(s.host_b)));
	}

	public bool has_host(InetAddress host) {
		return (host.equal(host_a.addr) || host.equal(host_b.addr));
	}
	public bool get_next_from_frame(Frame f, out Frame next) {
		int index_of = frames.index_of(f);
		next = null;

//		if (frames[index_of + 1] != null) {
		if (index_of + 1 < frames.size) {
			next = frames[index_of + 1];
			return true; 
		}

		return false;
	}
	internal void add_frame(Frame f) {
		frames.add(f);

		switch ((int) f.pcap_frame.ip_hdr.ip_proto) {
			case  PROTO_TCP:
				session_type = SESSION_TYPE.TCP; break;
			case  PROTO_UDP:
				session_type = SESSION_TYPE.UDP; break;
		}

		total_size += f.len;

		if (f.src.equal(host_a.addr))
			size_from_host_a += f.len;
		else
			size_from_host_b += f.len;

    	if (f.pcap_frame.tcp_hdr != null) {
	   		if (f.tcp_flags.SYN) {	   			
				if (f.tcp_flags.ACK) {
		   			seq_syn_ack = f.pcap_frame.tcp_hdr.th_seq;
		   			if (f.src.equal(host_a.addr)) {
		   				second_frame_host = host_a;
		   				// si la session demarre par un SYN/ACK alors on
		   				// n'a pas de premier hote...
		   				if (first_frame_host == null)
		   					first_frame_host = host_b;
		   			}
		   			else {
		   				second_frame_host = host_b;
		   				if (first_frame_host == null)
		   					first_frame_host = host_a;		   				
		   			}
	   			} else {
		   			seq_syn = f.pcap_frame.tcp_hdr.th_seq;
		   			if (f.src.equal(host_a.addr))
		   				first_frame_host = host_a;
		   			else
		   				first_frame_host = host_b;
	   			}
	   		} else if (first_frame_host == null) {
	   				first_frame_host = host_a;
		   			second_frame_host = host_b;
		   			seq_syn = f.pcap_frame.tcp_hdr.th_seq - 1;
		   			seq_syn_ack = f.pcap_frame.tcp_hdr.th_ack - 1;
	   		}

	    	if (f.src.equal(first_frame_host.addr)) {
	    		f.set_seq_ack(
		    		f.pcap_frame.tcp_hdr.th_seq - seq_syn,
		    		f.pcap_frame.tcp_hdr.th_ack - seq_syn_ack
    			);
	    	} else {
	    		f.set_seq_ack(
	    			f.pcap_frame.tcp_hdr.th_seq - seq_syn_ack,
	    			f.pcap_frame.tcp_hdr.th_ack - seq_syn
	    		);
	    	}
	    }
	}

	internal void build_flow_informations() {
		if (session_type == SESSION_TYPE.UDP) return;

		flow_informations = new FlowInformations(this);
	}

	public Frame get_from_flags(uint8 flags) {
		foreach (Frame f in frames) {
			if (f.tcp_flags.flags == flags)
				return f;
		}

		return (Frame) null;
	}

	public void display() {
		stdout.printf ("%s\n", to_string());
	}

	public bool detect_client_server() {
		if (first_frame_host != null) return true;

		foreach (Frame f in frames)	{
			if ((f.tcp_flags != null) && (f.tcp_flags.SYN & ! f.tcp_flags.ACK)) {
	   			if (f.src.equal(host_a.addr)) {
	   				first_frame_host = host_a;
	   				second_frame_host = host_b;
	   			}
	   			else {
	   				first_frame_host = host_b;
	   				second_frame_host = host_a;
	   			}

				return true;
			}
		}
		return false;
	}

	public Frame get_frame_by_num(uint32 n) {
		foreach (Frame f in frames)
			if (f.num == n) return f;

		return (Frame) null;
	}

	public string to_string() {
		return "%s <===> %s (nb frames : %d)".printf (host_a.to_string(), host_b.to_string(), frames.size);
	}

}

public class Sessions : ArrayList<Session> {
	public uint32 total_size = 0;
	public uint32 size_from_host_a = 0;
	public uint32 size_from_host_b = 0;

	public Session search_session(Session to_search) {
		foreach (Session session in this) {
			if (to_search.in_session(session))
				return session;
		}

		return (Session) null;
	}

	internal void add_session(Session to_add) {
		if (search_session(to_add) == (Session) null) {
			add(to_add);

			total_size += to_add.total_size;
			size_from_host_a += to_add.size_from_host_a;
			size_from_host_b += to_add.size_from_host_b;

		}
	}

	internal void add_frame(Frame frame) {
		Session to_add = frame.session;
		Session session = search_session(to_add);

		if (session != (Session) null) {
			session.add_frame(frame);

			total_size += frame.len;
			if (frame.src.equal(session.host_a.addr))
				size_from_host_a += frame.len;
			else
				size_from_host_b += frame.len;

		}
		else {
			add(to_add);
			to_add.add_frame(frame);

			total_size += to_add.total_size;
			size_from_host_a += to_add.size_from_host_a;
			size_from_host_b += to_add.size_from_host_b;

		}

	}

	internal void delete_by_host(InetAddress host) {
		Session session = null;
		int i = 0;

		while (i < size) {
			session = this[i];
			if (session.has_host(host)) {
				remove(session);

				total_size -= session.total_size;
				size_from_host_a -= session.size_from_host_a;
				size_from_host_b -= session.size_from_host_b;

				//free(session);
			} else
				i++;

		}
	}

	internal void delete_session(SocketInfos s) {
		Session session = null;
		int i = 0;

		while (i < size) {
			session = this[i];
			if (session.host_a.is_equals(s) || session.host_b.is_equals(s)) {
				remove(session);

				total_size -= session.total_size;
				size_from_host_a -= session.size_from_host_a;
				size_from_host_b -= session.size_from_host_b;
				//free(session);
			} else
				i++;

		}
	}

	public void display() {
		foreach (Session s in this) {
			s.display();
		}
	}

}

}