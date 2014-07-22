/*
 * tcp_flow.vala
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
 * Build a structured flow of a session
 *
 */

using Gee;

//const bool USE_SHARK = true;
namespace NetFrames {


public class FlowInformations :Object {
//	HashMap<uint32, uint32> matrice = new HashMap<uint32, uint32>();
	public HashMap<uint32, uint32> assoc_grouped_frames = new HashMap<uint32, uint32>();
	// HashMap<uint32, uint32> assoc_seq_acknowledged = new HashMap<uint32, uint32>();
	public TreeMap<uint32, uint32> assoc_seq_acknowledged = new TreeMap<uint32, uint32>();

	public ArrayList<seq_ack_frame> seq_ack_done = new ArrayList<seq_ack_frame>();

	unowned Session ref_session = null;

	public FlowInformations(Session s) {
		ref_session = s;
		FlowTCPSession fs = new FlowTCPSession(s);

		build_informations(fs);
		build_sequence_acknowledged(fs);		
	}


	bool seq_ack_already_done(seq_ack_frame to_test) {
		foreach (seq_ack_frame t in seq_ack_done) {
			if ((t.seq == to_test.seq) && (t.ack == to_test.ack))
				return true;
		}

		return false;
	}

	void seq_ack_add(seq_ack_frame to_add) {
		seq_ack_done.add(to_add);		
	}

	bool seq_ack_remove(seq_ack_frame to_remove) {
		foreach (seq_ack_frame t in seq_ack_done) {
			if ((t.seq == to_remove.seq) && (t.ack == to_remove.ack)) {
				seq_ack_done.remove(t);
				return true;
			}
		}

		return false;
	}

	void build_informations(FlowTCPSession fs) {

		fs.go_after_handshake();
		Frame reference = null;

		uint32 last_ack = 0;
		uint16 last_check = 0;

		Frame f = fs.get();

		do {

			if (last_ack != f.rel_ack) {
				reference = f;					

			 	if (f.len == 0) {
					seq_ack_done.remove(f.seq_ack);
					last_ack = 0;
					continue;
				}

				seq_ack_add(f.seq_ack);
				last_ack = f.rel_ack;					
				last_check = f.ip_checksum;
			} else {
				if (! seq_ack_already_done(f.seq_ack)) {			
						assoc_grouped_frames[f.num] = reference.num;
						seq_ack_done.add(f.seq_ack);
				} else {
					// stdout.printf ("DUPLICATE %s\n", frame_to_string(s, f));
				}
			}
		
		} 	while ( fs.next(out f)) ;


	}

	void build_sequence_acknowledged(FlowTCPSession fs) {
		int index1 = 0;
		int index2 = 0;

		while (index1 < fs.size) {
			// stdout.printf ("index1=%d, index2=%d   ", index1, index2);
			Frame f1 = fs.get(index1);
			if (f1.tcp_flags.ACK && (f1.len == 0)) {
				// stdout.printf ("\nF1  --> %s\n", frame_to_string(s1, f1));
				Frame f2 = null;
				 index2 = 0;
				while ((f2 == null) && (index2 <= index1)) {
					f2 = fs.get(index2);
					// stdout.printf ("F2  --> %s\n", frame_to_string(s1, f2));

					if ((index1 != index2) && ((f1.rel_seq == f2.rel_ack) && (f1.rel_ack  == f2.rel_seq + f2.len))) {
						/*
						stdout.printf ("%s\n", frame_to_string(s1, f1));
						stdout.printf ("ACK\n");
						stdout.printf ("%s\n\n", frame_to_string(s1, f2));
						*/
						assoc_seq_acknowledged[f1.num] = f2.num;
						break;
					}


					index2++;
					f2 = null;
				}
			}
			index1++;
		}
	}

	// cette fonction permet de récupérer la trame initiale d'un groupe de trames.
	// par exemple le serveur envoie une trame de 14Ko, celle-ci est fragmentée à la réception en 10 trame de 1,4Ko.
	// Cela permet de tenter d'afficher une vue "réseau" des trames avec les ACKs correspondant (ou à peu près)
	public bool has_reference_frame(Frame f, out Frame reference) {
		if (assoc_grouped_frames.has_key (f.num)) {
			reference = ref_session.get_frame_by_num(assoc_grouped_frames[f.num]);
			return true;
		}

		reference = null;
		return false;
	}

	public void display_groups() {
		TreeSet<uint32> matrice_values = new TreeSet<uint32>();

		stdout.printf ("==== RESULT GROUPS =====\nnumber : %d\n", assoc_grouped_frames.size);

	    foreach (uint32 key in assoc_grouped_frames.keys) {
	        stdout.printf ("%" + uint32.FORMAT + " => %" + uint32.FORMAT + "\n", assoc_grouped_frames[key], key);
			matrice_values.add(assoc_grouped_frames[key]);
	    }


		stdout.printf ("==== RESULT GROUPS =====\n");
	    foreach (uint32 value in matrice_values) {
	        stdout.printf ("%" + uint32.FORMAT + "\n", value);
	    }

		stdout.printf ("==== SEQ ACKNOWLEDGED =====\nnumber : %d\n", assoc_grouped_frames.size);

	    foreach (uint32 key in assoc_seq_acknowledged.keys) {
	        stdout.printf ("%" + uint32.FORMAT + " ACK %" + uint32.FORMAT + "\n", key, assoc_seq_acknowledged[key]);
	    }




	}

	public void display_seq_ack() {
		stdout.printf ("==== SEQ / ACK =====\n");

		foreach (seq_ack_frame sq in seq_ack_done) {
			stdout.printf ("%" + uint32.FORMAT + " => %" + uint32.FORMAT + "\n", sq.seq, sq.ack);
		}
	}
}

public class FlowTCPSession {
	public enum STATUS {
	/* STATUS describes the status of a tcp session */
		NIHL = 0,
		SYN_SENT,
		SYN_RECEIVED,
		ESTABLISHED,
		FIN_WAIT_1,
		FIN_WAIT_2__CLOSE_WAIT,
		TIME_WAIT__LAST_ACK,
		LAST_ACK,
		CLOSED,
		RESET,
		EXPIRED
	}
	
	public int size { get { return session.frames.size; } }

	InetAddress client;
	InetAddress server;

	Session session = null;

	public STATUS status = STATUS.NIHL;

	private int _index = -1;
	
	public FlowTCPSession(Session s) {
		session = s;
	}


	public bool go_after_handshake() {
		Frame f = null;
		if (first(out f)) {
			while (next(out f) && (status != STATUS.ESTABLISHED)) {

			}

			if (next(out f))
				return true;
		}

		return false;
	}
/*
	n°seq = dernier n° ack
ack = dernier seq reçu + données
*/
	public void determine_status() {
		Frame f1 = session.frames[_index];

		if (f1.tcp_flags.SYN & ! f1.tcp_flags.ACK)
			status = STATUS.SYN_SENT;

		if (f1.tcp_flags.SYN &  f1.tcp_flags.ACK)
			status = STATUS.SYN_RECEIVED;

		if ((! f1.tcp_flags.SYN & f1.tcp_flags.ACK) &&
			((f1.rel_seq == 1) && (f1.rel_ack == 1)))
			status = STATUS.ESTABLISHED;

	}

	public bool eos() {
		return _index == session.frames.size -1;
	}

	public bool next (out Frame f) {
		f = null;

		if (_index + 1 < session.frames.size) {
			_index++;

			f = get();

			return true;
		}
		return false;
	}

	public bool has_next () {
		return (_index + 1 < session.frames.size);
	}

	public bool first (out Frame f) {
		assert(session.frames != null);
		f = null;

		if (session.frames.size == 0) {
			return false;
		}

		_index = 0;
		f = get();

		return true;
	}

	public new Frame get (int p_index = -1) {
		if (p_index != -1) {
			return session.frames[p_index];
		}

		if (_index >= session.frames.size) 
			return (Frame) null;

		determine_status();
		return session.frames[_index];
	}

	public bool previous () {
		if (_index > 0) {
			_index--;
			return true;
		}
		return false;
	}


	public bool get_previous (out Frame f) {
		f = null;
		if (_index <= 0) return false;

		f = session.frames[_index - 1];

		return true;
	}

	public bool has_previous () {
		return (_index - 1 >= 0);
	}

	public bool last () {
		if (session.frames.size == 0) {
			return false;
		}
		_index = session.frames.size - 1;
		return true;
	}

	public int index () {
		return _index;
	}

}

}