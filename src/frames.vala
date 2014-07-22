/*
 * frames.vala
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
 * Regroupement de classes permettant la création d'un ensemble de trames
 * à partir de la lecture d'un fichier au format PCAP standard ainsi
 * que quelques manipulations simples (supprimer une trame par exemple).
 */

using Gee;

//const bool USE_SHARK = true;
namespace NetFrames {

MemoryInputStream mis = null;

/*
 * La classe PCapFrame est la représentation de ce qui est lu à partir d'un fichier
 * au format PCAP standard :
 *      - entête d'une pcap d'une trame lue
 *      - entête ethernet
 *      - entête IP
 *      - entête TCP ou UDP
 *      - données / payload
 */

 public class seq_ack_frame {
	public uint32 seq;
	public uint32 ack;

	public seq_ack_frame.from_uint32(uint32 s, uint32 a) {
		seq = s; ack = a;
	}

	public seq_ack_frame(Frame f) {
		seq = f.rel_seq;
		ack = f.rel_ack;
	}
}

public class PCapFrame : Object {
	public PCapRecordHeader rec = null;
	public EtherHeader 		ether_hdr = null;
	public IPHeader			ip_hdr = null;
	public TCPHeader		tcp_hdr = null;
	public UDPHeader		udp_hdr = null;
	public uint8[]			datas = null;

	public PCapFrame(uint8[] buffer) {
		hexdump(buffer, buffer.length);
	}

	~PCapFrame() {
		datas.resize(0);
	}

	public PCapFrame.from_buffer(PCapRecordHeader p_rec, uint8[] pkt_data) {
		int cursor = 0;
		int datas_size = 0;

		rec = p_rec;
		ether_hdr = new EtherHeader.from_buffer(pkt_data, ref cursor);

  		if (ether_hdr.ether_type != 0x0800) return;

		ip_hdr = new IPHeader.from_buffer(pkt_data, ref cursor);

		if (ip_hdr.ip_proto == PROTO_TCP) {
			tcp_hdr = new TCPHeader.from_buffer(pkt_data, ref cursor);
			datas_size = (int) (ip_hdr.ip_len - ip_hdr.size() - tcp_hdr.th_offset * 4);
		}

		if (ip_hdr.ip_proto == PROTO_UDP) {
			udp_hdr = new UDPHeader.from_buffer(pkt_data, ref cursor);
			datas_size = (int) (udp_hdr.uh_len - udp_hdr.size());
		}

		if (datas_size > 0) {
			datas = new uint8[datas_size];
			for (int i = 0; i < datas.length; i++) datas[i] = (uint8) (pkt_data[cursor++]);
		}
	}

	public PCapFrame.from_datainputstream(PCapRecordHeader p_rec, DataInputStream dis, bool compat_mode) {
		int datas_size = 0;

		rec = p_rec;
		ether_hdr = new EtherHeader.from_inputstream(dis, compat_mode);

		if (ether_hdr.ether_type != 0x0800) return;

		ip_hdr = new IPHeader.from_inputstream(dis, compat_mode);

		if (ip_hdr.ip_proto == PROTO_TCP) {
			tcp_hdr = new TCPHeader.from_inputstream(dis, compat_mode);
			datas_size = (int) (ip_hdr.ip_len - ip_hdr.size() - tcp_hdr.th_offset * 4);
		}

		if (ip_hdr.ip_proto == PROTO_UDP) {
			udp_hdr = new UDPHeader.from_inputstream(dis, compat_mode);
			datas_size = (int) (udp_hdr.uh_len - udp_hdr.size());
		}

		if (datas_size > 0) {
			datas = new uint8[datas_size];

			if (compat_mode)
				for (int i = 0; i < datas.length; i++) datas[i] = dis.read_byte();
			else
				dis.read(datas);
		}

	}

	public void write_stream(DataOutputStream dos) {
		rec.write_stream(dos);
		ether_hdr.write_stream(dos);
		ip_hdr.write_stream(dos);

		if (ip_hdr.ip_proto == PROTO_TCP)
			tcp_hdr.write_stream(dos);

		if (ip_hdr.ip_proto == PROTO_UDP)
			udp_hdr.write_stream(dos);

		if (datas != null)
			dos.write(datas);
	}

	public void display() {
		stdout.printf ("%" + uint32.FORMAT + " / %" + uint32.FORMAT + "    %" + uint32.FORMAT + "/%" + uint32.FORMAT + "\n",
			rec.ts.tv_sec, rec.ts.tv_usec,
			rec.incl_len, rec.orig_len
			);

		stdout.printf ("ether type : %x\n", ether_hdr.ether_type);

		hexdump(ether_hdr.ether_shost, 6);
		hexdump(ether_hdr.ether_dhost, 6);

		if (ip_hdr != null)
			ip_hdr.display();

	}
}

public class Frame : Object {
	public PCapFrame pcap_frame = null;

	public 	InetAddress src { get { return pcap_frame.ip_hdr.src; } set {  pcap_frame.ip_hdr.src = value; } }
	public 	InetAddress dst  { get { return pcap_frame.ip_hdr.dst; }  set {  pcap_frame.ip_hdr.dst = value; } }
	public 	uint16 src_port { get { if (pcap_frame.tcp_hdr != null)
										return pcap_frame.tcp_hdr.th_sport;
									return pcap_frame.udp_hdr.uh_sport;
										}
									}

	public 	uint16 dst_port { get { if (pcap_frame.tcp_hdr != null)
										return pcap_frame.tcp_hdr.th_dport;
									return pcap_frame.udp_hdr.uh_dport;
										} }

	public 	uint32 len { get { return pcap_frame.datas.length; } }

	public uint32 num;
	public 	GLib.TimeVal time { get { return pcap_frame.rec.ts; } set { pcap_frame.rec.ts.tv_sec = value.tv_sec; pcap_frame.rec.ts.tv_usec = value.tv_usec; } }
	public 	string dissect = "";
	public 	string proto;

	public TCPFlags tcp_flags {
			get {
				if (pcap_frame.tcp_hdr != null)
					return pcap_frame.tcp_hdr.tcp_flags;
				else
					return null;
				}
			}

	public seq_ack_frame seq_ack = null;
	public uint32 rel_seq { get { assert(seq_ack != null); return seq_ack.seq; } }
	public uint32 rel_ack  { get { return seq_ack.ack; } }

	public uint16 ip_checksum { get { return pcap_frame.ip_hdr.ip_sum; } }

	Connection _connection = null;
	Session _session = null;
	public Connection connection { get { return _connection; } }
	public Session session { get { return _session; } }

	public Frame.PCap(PCapFrame f) {
		this.pcap_frame = f;
 	/*
		time.tv_sec = f.rec.ts.tv_sec;
		time.tv_usec = f.rec.ts.tv_usec;
	*/
		_connection = create_connection();
		_session = create_session();
	}

	public Frame.Shark_Array(string[] ar_datas) {
		set_datas(ar_datas);
		// _connection = create_connection();
		//	_session = create_session();
	}

	public Frame.Shark_String(string s) {
		set_datas(strip_tshark_line(s));
//		_connection = create_connection();
//		_session = create_session();

	}

	public bool equal(Frame f) {
		return src.equal(f.src) && dst.equal(f.dst) &&
		(src_port == f.src_port) && (dst_port == f.dst_port) &&
		(pcap_frame.ip_hdr.ip_id == f.pcap_frame.ip_hdr.ip_id);
	}


	public bool has_host(InetAddress host) {
		return (host.equal(src) || host.equal(dst));
	}

	public bool has_port(uint16 port) {
		return ((src_port == port) || (dst_port == port));
	}

	void set_datas(string[] ar_datas) {
		num = (uint32) int.parse(ar_datas[0]);
		proto = ar_datas[5];

		if (ar_datas.length > 8) {
			dissect = ar_datas[10];
		} else
			dissect = ar_datas[7];
	}

	internal void set_seq_ack(uint32 s, uint32 a) {
		/*
		if (has_port(3470)) {
			display();
			stdout.printf ("se_ack %d / %d\n", (int) s, (int) a);
		}
		*/
		seq_ack = new seq_ack_frame.from_uint32(s, a);
	}

	public void display() {
		DateTime dt =  new DateTime.from_timeval_utc (time) ;
		string dateformat = dt.format("%T.");
		dateformat = dateformat + dt.get_microsecond().to_string();

		stdout.printf ("num: %" + uint16.FORMAT + " time : %s src:%s:%d dst:%s:%d  (len: %d)\n",
			num, dateformat, src.to_string(), src_port, dst.to_string(), dst_port, len);

		if (dissect != "")
			stdout.printf ("%s\n", dissect);

	}

	public void display_flags() {
		stdout.printf ("num: %" + uint16.FORMAT + " src:%s:%d dst:%s:%d  (len: %d) flags:%s\n",
			num, src.to_string(), src_port, dst.to_string(), dst_port, len, tcp_flags.to_string());
	}

	public Connection create_connection() {
		return new Connection(src, dst);
	}

	public Session create_session() {
		return new Session(new SocketInfos(src, src_port), new SocketInfos(dst, dst_port));
	}

}
/*
public int64 comparator(Frame a, Frame b) {
	return (int64) (a.num - b.num);
}
*/
        public static int64 comparator(void *a, void *b) {
            return (int64) ((Frame *) a)->num - (int64) ((Frame *) b)->num;
        }

public class Frames : SortedList<Frame> {
	string filename;

	public Frames() {
		base(comparator);
    }

	bool process_line (IOChannel channel, IOCondition condition, out Frame o_frame) {
		Frame frame;
		if (condition == IOCondition.HUP) {
			stdout.printf ("The stream has been closed.\n");
			return false;
		}

		try {
			string line;
			channel.read_line (out line, null, null);
			if (line == null) return false;

			string[] ar_datas = strip_tshark_line(line);
			if (is_ethernet(ar_datas[2])) return true;

			frame = new Frame.Shark_Array(ar_datas);

			o_frame = frame;
		} catch (IOChannelError e) {
			stdout.printf ("IOChannelError: %s\n", e.message);
			return false;
		} catch (ConvertError e) {
			stdout.printf ("ConvertError: %s\n",  e.message);
			return false;
		}

		return true;
	}

	public Frame search_frame(Frame to_search) {
		foreach (Frame f in this)
			if (f.equal(to_search)) return f;

		return (Frame) null;
	}

	public Frame get_frame_by_num(uint32 num) {
		foreach (Frame f in this)
			if (f.num == num) return f;

		return (Frame) null;
	}

	public void tshark_decode(string filename, Capture capture) {
		MainLoop loop = new MainLoop ();
		string[] spawn_args;

		unowned string? test = GLib.Environment.get_variable("OS");

		if ((test != null) && test.down().contains("windows"))
			spawn_args = {"tshark.exe", "-r", filename, "-n"};
		else
			spawn_args = {"tshark", "-r", filename, "-n"};

		string[] spawn_env = Environ.get ();
		Pid child_pid;

		int standard_input;
		int standard_output;
		int standard_error;

		try {

			Process.spawn_async_with_pipes (null,
				spawn_args,
				spawn_env,
				SpawnFlags.SEARCH_PATH | SpawnFlags.DO_NOT_REAP_CHILD,
				null,
				out child_pid,
				out standard_input,
				out standard_output,
				out standard_error);

			IOChannel output = new IOChannel.unix_new (standard_output);
			output.add_watch (IOCondition.IN | IOCondition.HUP, (channel, condition) => {
				Frame f = null;
				bool result =  process_line (channel, condition, out f);

				if ( f != null) {
					Frame frame = get_frame_by_num(f.num);
					if (frame != null) {
						frame.dissect = f.dissect;
						frame.proto = f.proto;
//						frame.time.tv_sec = f.time.tv_sec;
					}
//					free(f);
				}

				return result;
			});

			ChildWatch.add (child_pid, (pid, status) => {
				Process.close_pid (pid);
				loop.quit ();
			});

			loop.run ();
		} catch (SpawnError e) {
			stdout.printf ("tshark.exe not detected\n");
		}

	}

	public void load_pcap_file(string filename, Capture capture, bool compatibility_mode = false) {
		stdout.printf ("Loading with libpcap function\n");
		this.filename = filename;
		int count = 1;
		var err = new char[PCap.ERRBUF_SIZE];
		var read = 	PCap.Capture.open_offline_file(filename, err);

		unowned PCap.Result res;
		unowned uint8[] packet_data;
		PCap.packet_header header; // = new PCap.packet_header();

 		// while((res = read.next_ex( out header, out packet_data)) >= 0)	{
 		while((packet_data = read.next( out header)) != null)	{
			PCapRecordHeader rec = new PCapRecordHeader.from_PCap_header(header);
			PCapFrame pcap_frame = new PCapFrame.from_buffer(rec, packet_data);

			if ((pcap_frame.ip_hdr != null) &&
			   ((pcap_frame.ip_hdr.ip_proto == PROTO_TCP) || (pcap_frame.ip_hdr.ip_proto == PROTO_UDP))) {
				Frame frame = new Frame.PCap(pcap_frame);
				frame.num = count;
				add(frame);
/*
				capture.add_host(frame);

				// On ajoute une connexion, si elle existe déjà on la récupère
				// et on ajoute la trame à la connexion
				Connection c = capture.add_connection(new Connection(frame.src, frame.dst));

				assert(c != null);

				c.sessions.add_frame(frame);
*/
			}
			count++;
		}


	}
/*
	public void load_pcap_file(string filename, Capture capture, bool compatibility_mode = false) {
//		stdout.printf ("Loading with internal function\n");
		this.filename = filename;
		DataInputStream dis	= null;
		int64 size=0;
		int num = 1;
		try {
			File file = File.new_for_path (filename);
			FileInfo info = file.query_info ("*", FileQueryInfoFlags.NONE);

			size = info.get_size();
			uint8[] buffer = new uint8[size];

			if (compatibility_mode) {
				MemoryOutputStream os = new MemoryOutputStream (null, GLib.realloc, GLib.free);
				dis = new DataInputStream (file.read ());
				size_t bytes_read;

				dis.read_all(buffer, out bytes_read);

				dis.close();

				mis = new MemoryInputStream.from_data (@buffer, GLib.free);
				dis = new DataInputStream (@mis);
			} else
				dis = new DataInputStream (file.read ());

			dis.set_byte_order (DataStreamByteOrder.LITTLE_ENDIAN);

			capture.pcap_header = new PCapHeader.from_datainputstream(dis, compatibility_mode);

			if (compatibility_mode) {
				while (mis.tell() != size) {
					PCapRecordHeader rec = new PCapRecordHeader.from_datainputstream(dis, compatibility_mode);
					int64 initial_position = mis.tell();
					PCapFrame pcap_frame = new PCapFrame.from_datainputstream(rec, dis, compatibility_mode);

					if ((pcap_frame.ip_hdr != null) &&
					   ((pcap_frame.ip_hdr.ip_proto == PROTO_TCP) || (pcap_frame.ip_hdr.ip_proto == PROTO_TCP))) {
						Frame frame = new Frame.PCap(pcap_frame);
						frame.num = num;
						add(frame);
						capture.add_host(frame);

						// On ajoute une connexion, si elle existe déjà on la récupère
						// et on ajoute la trame à la connexion
						Connection c = capture.add_connection(new Connection(frame.src, frame.dst));

						assert(c != null);
						c.sessions.add_frame(frame);
					}
					num++;
					mis.seek(initial_position + rec.incl_len, SeekType.SET);
				}
			} else {
				while (dis.tell() != size) {
					PCapRecordHeader rec = new PCapRecordHeader.from_datainputstream(dis, compatibility_mode);

					int64 initial_position = dis.tell();

					PCapFrame pcap_frame = new PCapFrame.from_datainputstream(rec, dis, compatibility_mode);

					if ((pcap_frame.ip_hdr != null) &&
					   ((pcap_frame.ip_hdr.ip_proto == PROTO_TCP) || (pcap_frame.ip_hdr.ip_proto == PROTO_TCP))) {
						Frame frame = new Frame.PCap(pcap_frame);
						frame.num = num;
						add(frame);
						capture.add_host(frame);

						// On ajoute une connexion, si elle existe déjà on la récupère
						// et on ajoute la trame à la connexion
						Connection c = capture.add_connection(new Connection(frame.src, frame.dst));

						assert(c != null);
						c.sessions.add_frame(frame);
					}
					num++;
					dis.seek(initial_position + rec.incl_len, SeekType.SET);
				}
			}
			dis.close();
			if (compatibility_mode)
				mis.close();
		} catch (Error e) {
			stdout.printf ("-- ERREUR -- %s\n", e.message);
		}
	}
	*/
//	public void save_pcap(string output_filename, Capture capture) {
	public void save_pcap(string output_filename) {
		var err = new char[PCap.ERRBUF_SIZE];

		var read = PCap.Capture.open_dead ((PCap.LinkLayer) 1, 65535);
		var dump = read.open_dump_file(output_filename);

		assert(read != null);
		assert(dump != null);

		uint8[] datas = new uint8[16384];

		foreach (Frame f in this) {
			var mem = new MemoryOutputStream (null, realloc , null);
			var dos = new DataOutputStream (@mem);

			f.pcap_frame.ether_hdr.write_stream(dos);
			f.pcap_frame.ip_hdr.write_stream(dos);

			if (f.pcap_frame.ip_hdr.ip_proto == PROTO_TCP)
				f.pcap_frame.tcp_hdr.write_stream(dos);

			if (f.pcap_frame.ip_hdr.ip_proto == PROTO_UDP)
				f.pcap_frame.udp_hdr.write_stream(dos);

			if (f.pcap_frame.datas != null)
				dos.write (f.pcap_frame.datas);

			PCap.packet_header p = PCap.packet_header();

			p.ts.tv_usec = f.pcap_frame.rec.ts.tv_usec;
			p.ts.tv_sec = f.pcap_frame.rec.ts.tv_sec;


			p.caplen = (int32) f.pcap_frame.rec.incl_len;
			p.len = (int32) f.pcap_frame.rec.orig_len;

			dump.dump(p, (uint8[]) mem.data);
		}

	}

	internal void delete_host(InetAddress host) {
		Frame frame = null;
		int i = 0;
		if (size <= 0) return;

		while (i < size) {
			frame = get_at(i);
			if (host.equal(frame.src) || host.equal(frame.dst)) {
				remove(frame);
				//free(frame);
			} else
				i++;
		}
	}

	internal void delete_connection(Connection c) {
		Frame frame = null;
		int i = 0;
		if (size <= 0) return;

		while (i < size) {
			frame = get_at(i);
			if ((c.host_a.equal(frame.src) && c.host_b.equal(frame.dst)) ||
			    (c.host_a.equal(frame.dst) && c.host_b.equal(frame.src))) {
				remove(frame);
			} else
				i++;
		}
	}

	internal void delete_session_by_host(SocketInfos s) {
		Frame frame = null;
		int i = 0;
		while (i < size) {
			frame = get_at(i);
			if ((s.addr.equal(frame.src) && (s.port == frame.src_port)) ||
				(s.addr.equal(frame.dst) && (s.port == frame.dst_port))) {
				remove(frame);
				//free(frame);
			} else
				i++;
		}
	}

	internal void delete_session(Session  s) {
		Frame frame = null;
		int i = 0;
		while (i < size) {
			frame = get_at(i);

			if (((s.host_a.addr.equal(frame.src) && (s.host_a.port == frame.src_port)) &&
				 (s.host_b.addr.equal(frame.dst) && (s.host_b.port == frame.dst_port))) ||

				((s.host_b.addr.equal(frame.src) && (s.host_b.port == frame.src_port)) &&
				 (s.host_a.addr.equal(frame.dst) && (s.host_a.port == frame.dst_port)))) {

				remove(frame);
			} else
				i++;
		}
	}

	public void display() {
		stdout.printf ("display Frames\n");
		foreach (Frame f in this) {
			f.display();
		}
	}
}
}

/*

thsark files
comerr32.dll
k5sprt32.dll
krb5_32.dll
libGeoIP-1.dll
libcares-2.dll
libgcrypt-11.dll
libgnutls-26.dll
libgpg-error-0.dll
libsmi-2.dll
libtasn1-3.dll
libwireshark.dll
libwsutil.dll
lua5.1.dll
tshark.exe
wiretap-1.10.0.dll
wpcap.dll
*/
