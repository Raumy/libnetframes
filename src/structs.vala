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
 * Structures de bases relatif aux différentes entêtes réseaux
 * ainsi qu'aux entêtes spécifiques au format PCAP.
 *
 */

namespace NetFrames {

    public const int ETHER_ADDR_LEN = 6;
    public const int ETHER_TYPE_LEN = 2;
    public const int ETHER_CRC_LEN=4;
    public const int ETHER_HDR_LEN	= (ETHER_ADDR_LEN*2+ETHER_TYPE_LEN);
    public const int ETHER_MIN_LEN	= 64;
    public const int ETHER_MAX_LEN = 1518;

    public const int PROTO_TCP = 0x06; 	// TCP 	Transmission Control Protocol 	RFC 793
    public const int PROTO_UDP = 0x11; 	// TCP 	Transmission Control Protocol 	RFC 793


    /*
    	===========================================
        *
        *  Déclaration des types de trames
        *
        ===========================================
    */

    /*
    type
    	IPAddr = Cardinal;     // An IP address.
    	IPMask = Cardinal;     // An IP subnet mask.
    */

    struct IpOptionsInfos {
        uint8 ttl;
        uint8 tos;
        uint8 flags;
        uint8 optSize;
        // OptData opt_data;
    }


    public class EtherHeader : Object {
        public uint8 ether_dhost[6];
        public uint8 ether_shost[6];
        public uint16	ether_type;

        public EtherHeader.from_buffer(uint8[] pkt, ref int cursor) {
            for (int i = 0; i < 6; i++) {
                ether_shost[i] = pkt[i + cursor];
                ether_dhost[i] = pkt[i + cursor + 6];
            }

            cursor += 12;
            ether_type = uint16.from_network ((uint16) pkt[cursor]);
            cursor += (int) sizeof(uint16);
        }

        public EtherHeader.from_inputstream(DataInputStream dis, bool compat_mode = false) {
            if (compat_mode) {
                /*
                 *  Me demandez pas pourquoi mais sous linux j'arrive pas à utiliser
                 * la fonction seek et quand je veux utiliser un datastreaminput
                 * sur un memorystream pour lire un tableau, ça perd la position...
                 * Je lis donc les tableaux "à la main".....
                */
                for (int i = 0; i < 6; i++) ether_shost[i] = dis.read_byte();
                for (int i = 0; i < 6; i++) ether_dhost[i] = dis.read_byte();
            } else {
                dis.read(ether_shost);
                dis.read(ether_dhost);
            }

            ether_type = uint16.from_big_endian (dis.read_uint16());
        }

        public void write_stream(DataOutputStream dos) {
            dos.write(ether_shost);
            dos.write(ether_dhost);
            // dos.put_uint16(uint16.to_network(ether_type));
            dos.put_uint16(ether_type);
        }

        public static ulong size() {
            return sizeof(uint8) * 6 + sizeof(uint8) * 6 + sizeof(uint16);
        }

        public void display() {
            stdout.printf ("ether_shost : ");
            for (int i = 0; i < 6; i++)
                stdout.printf("%.2x ", ether_shost[i]);

            stdout.printf ("     ether_dhost : ");
            for (int i = 0; i < 6; i++)
                stdout.printf("%.2x ", ether_dhost[i]);

            stdout.printf("     ether type : %.4x\n", ether_type);
        }
    }


    public class  IPHeader  : Object {
        public uint8 ip_vhl;
        public 	uint8 ip_tos;
        public 	uint16 ip_len;
        public 	uint16 ip_id;// identification
        public 	uint16 ip_off;  // fragment offset field
        public 	uint8 ip_ttl;   // time to live
        public 	uint8 ip_proto;  // protocol
        public 	uint16 ip_sum;  // checksum
        public 	uint32 ip_src;	// source and dest address
        public 	uint32 ip_dst;

        public 	InetAddress src;
        public 	InetAddress dst;

        ~IPHeader() {
            src= null;
            dst = null;
        }

        public IPHeader.from_buffer(uint8[] pkt, ref int cursor) {
            ip_vhl = (uint8) pkt[cursor++];
            ip_tos = (uint8) pkt[cursor++];

            ip_len = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            ip_id = uint16.from_network (read_uint16_buffer(pkt, ref cursor));

            ip_off = read_uint16_buffer(pkt, ref cursor);
            ip_ttl = (uint8) pkt[cursor++];
            ip_proto = (uint8) pkt[cursor++];
            ip_sum = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            ip_src = read_uint32_buffer(pkt, ref cursor);
            ip_dst = read_uint32_buffer(pkt, ref cursor);

            src = new InetAddress.from_bytes(convert_uint32_into_uint8(ip_src), SocketFamily.IPV4);
            dst = new InetAddress.from_bytes(convert_uint32_into_uint8(ip_dst), SocketFamily.IPV4);
        }

        public IPHeader.from_inputstream(DataInputStream dis, bool compat_mode = false) {
            ip_vhl = dis.read_byte();
            ip_tos = dis.read_byte();
            ip_len = uint16.from_big_endian (dis.read_uint16());
            ip_id = uint16.from_big_endian (dis.read_uint16());

            ip_off = dis.read_uint16();
            ip_ttl = dis.read_byte();
            ip_proto = dis.read_byte();
            ip_sum = uint16.from_big_endian (dis.read_uint16());

            ip_src = dis.read_uint32();
            ip_dst = dis.read_uint32();

            src = new InetAddress.from_bytes(convert_uint32_into_uint8(ip_src), SocketFamily.IPV4);
            dst = new InetAddress.from_bytes(convert_uint32_into_uint8(ip_dst), SocketFamily.IPV4);
        }

        public void write_stream(DataOutputStream dos) {
            dos.put_byte(ip_vhl);
            dos.put_byte(ip_tos);

            dos.put_uint16(ip_len);
            dos.put_uint16(ip_id);
            dos.put_uint16(uint16.to_network(ip_off));
            dos.put_byte(ip_ttl);
            dos.put_byte(ip_proto);

            dos.put_uint16(ip_sum);
            dos.put_uint32(uint32.to_network(ip_src));
            dos.put_uint32(uint32.to_network(ip_dst));
        }

        public static ulong size() {
            return sizeof(uint8) * 4 + sizeof(uint16) * 4 + sizeof(uint32) * 2;
        }

        public void display() {
            stdout.printf ("%s => %s (len : %" + uint16.FORMAT + ")\n", new InetAddress.from_bytes(convert_uint32_into_uint8(ip_src), SocketFamily.IPV4).to_string(),
                           new InetAddress.from_bytes(convert_uint32_into_uint8(ip_dst), SocketFamily.IPV4).to_string(),
                           ip_len);
            stdout.printf ("tos : %d, id: %x (%d), offset: %d, ttl: %d, checksum:%x\n", ip_tos, ip_id, ip_id, ip_off, ip_ttl, ip_sum);
        }

    }

    public class  TCPHeader  : Object {
        public uint16 th_sport	;	// source port
        public uint16 th_dport	;	// destination port
        public uint32 th_seq;	//sequence number
        public uint32 th_ack;	// acknowledgement number

        public uint8 th_offset;	// data offset, rsvd
        public uint8 th_flags;

        public uint16 th_win;		// window
        public uint16 th_sum;		// checksum
        public uint16 th_urg;		// urgent pointer
        public uint8[] options = null;

        public TCPFlags tcp_flags = null;
        public int length { get { return th_offset * 4; } }

        ~TCPHeader() {
            options.resize(0);
            options = null;
        }


        public TCPHeader.from_buffer(uint8[] pkt, ref int cursor) {
            uint16 tmp = 0;
            uint8 left;
            uint8 right;

            th_sport = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            th_dport = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            th_seq = uint32.from_network (read_uint32_buffer(pkt, ref cursor));
            th_ack = uint32.from_network (read_uint32_buffer(pkt, ref cursor));

            th_offset = (uint8) ((uint8) pkt[cursor++] >> 4);
            th_flags = (uint8) ((uint8) pkt[cursor++] & 0x003F);
            /*
            left = (uint8) (dis.read_byte());
            right = (uint8) (dis.read_byte());

            th_offset = (uint8) (left >> 4);
            th_flags = (uint8) (right & 0x003F);
            */
            tcp_flags = new TCPFlags(th_flags);
            th_win = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            th_sum = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            th_urg = uint16.from_network (read_uint16_buffer(pkt, ref cursor));

            if (th_offset != 0) {
                ulong options_size = length - size();

                if (options_size != 0) {
                    options = new uint8[12];
                    for (int i = 0; i < options.length; i++) options[i] = (uint8) pkt[cursor++];
                }
            }
        }

        public TCPHeader.from_inputstream(DataInputStream dis, bool compat_mode = false) {
            uint16 tmp = 0;
            uint8 left;
            uint8 right;

            th_sport = uint16.from_big_endian (dis.read_uint16());
            th_dport = uint16.from_big_endian (dis.read_uint16());
            th_seq = uint32.from_big_endian (dis.read_uint32());
            th_ack = uint32.from_big_endian (dis.read_uint32());

            th_offset = (uint8) (dis.read_byte() >> 4);
            th_flags = (uint8) (dis.read_byte() & 0x003F);
            /*
            left = (uint8) (dis.read_byte());
            right = (uint8) (dis.read_byte());

            th_offset = (uint8) (left >> 4);
            th_flags = (uint8) (right & 0x003F);
            */
            th_win = uint16.from_big_endian (dis.read_uint16());
            th_sum = uint16.from_big_endian (dis.read_uint16());
            th_urg = uint16.from_big_endian (dis.read_uint16());

            if (th_offset != 0) {
                ulong options_size = length - size();

                if (options_size != 0) {
                    options = new uint8[12];
                    if (compat_mode)
                        for (int i = 0; i < options.length; i++) options[i] = dis.read_byte();
                    else
                        dis.read(options);
                }
            }
        }

        public void write_stream(DataOutputStream dos) {
            dos.put_uint16(th_sport);
            dos.put_uint16(th_dport);

            dos.put_uint32(th_seq);
            dos.put_uint32(th_ack);

            dos.put_byte(th_offset << 4);
            dos.put_byte(th_flags);


            dos.put_uint16(th_win);
            dos.put_uint16(th_sum);
            dos.put_uint16(uint16.to_network(th_urg));

            if (options != null)
                dos.write(options);
        }


        public static ulong size() {
            return sizeof(uint8) * 2 + sizeof(uint16) * 5 + sizeof(uint32) * 2;
        }

        public void display() {
            stdout.printf ("s_port: %d, d_port: %d, offset: %d, %s (%d), win:%d, sum:0x%x\n", th_sport, th_dport, th_offset * 4, to_binary(th_flags, 6), th_flags, th_win, th_sum);
        }

    }



    public class  UDPHeader  : Object {
        public uint16 uh_sport	;	// source port
        public uint16 uh_dport	;	// destination port
        public uint16 uh_len;	//sequence number
        public uint16 uh_sum;		// checksum

        public UDPHeader.from_buffer(uint8[] pkt, ref int cursor) {
            uh_sport = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            uh_dport = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            uh_len = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
            uh_sum = uint16.from_network (read_uint16_buffer(pkt, ref cursor));
        }

        public UDPHeader.from_inputstream(DataInputStream dis, bool compat_mode = false) {
            uh_sport = uint16.from_big_endian (dis.read_uint16());
            uh_dport = uint16.from_big_endian (dis.read_uint16());
            uh_len = uint16.from_big_endian (dis.read_uint16());
            uh_sum = uint16.from_big_endian (dis.read_uint16());
        }

        public void write_stream(DataOutputStream dos) {
            dos.put_uint16(uint16.to_network(uh_sport));
            dos.put_uint16(uint16.to_network(uh_dport));
            // dos.put_uint16(uint16.to_network(uh_len));
            dos.put_uint16(uh_len);
            dos.put_uint16(uint16.to_network(uh_sum));
        }

        public static ulong size() {
            return sizeof(uint16) * 4;
        }

    }

    struct frame_hdrs {
        EtherHeader ether_hdr;
        IPHeader	ip_hdr;
        TCPHeader	tcp_hdr;
    }


    public class PCapHeader  : Object {
        public uint32 magic_number;   /* magic number */
        public uint16 version_major;  /* major version number */
        public uint16 version_minor;  /* minor version number */
        public int32  thiszone;       /* GMT to local correction */
        public uint32 sigfigs;        /* accuracy of timestamps */
        public uint32 snaplen;        /* max length of captured packets, in octets */
        public uint32 network;        /* data link type */

        public PCapHeader.from_datainputstream(DataInputStream dis, bool compat_mode = false) {
            magic_number = dis.read_uint32();
            version_major = dis.read_uint16();
            version_minor = dis.read_uint16();
            thiszone = dis.read_int32();
            sigfigs = dis.read_uint32();
            snaplen = dis.read_uint32();
            network = dis.read_uint32();
        }

        public void write_stream(DataOutputStream dos) {
            dos.put_uint32(magic_number);
            dos.put_uint16(version_major);
            dos.put_uint16(version_minor);
            dos.put_int32(thiszone);
            dos.put_uint32(sigfigs);
            dos.put_uint32(snaplen);
            dos.put_uint32(network);
        }

        public void display() {
            stdout.printf ("magic number : %lu, major.minor : %d.%d\n", magic_number, version_major, version_minor);
            stdout.printf ("snaplen: %d, linklayer : %d\n", (int) snaplen, (int) network);
        }



    }

    public class PCapRecordHeader  : Object  {
        /*
        public uint32 ts_sec = 0;         // timestamp seconds
        public uint32 ts_usec = 0;        // timestamp microseconds
        */
        public GLib.TimeVal ts;
        public uint32 incl_len = 0;       /* number of octets of packet saved in file */
        public uint32 orig_len = 0;       /* actual length of packet */

        public PCapRecordHeader.from_PCap_header(PCap.packet_header header) {
            ts.tv_sec = header.ts.tv_sec;
            ts.tv_usec = header.ts.tv_usec;
            incl_len = header.caplen;
            orig_len = header.len;
        }

        public PCapRecordHeader.from_datainputstream(DataInputStream dis, bool compat_mode = false) {
            ts.tv_sec = (time_t) dis.read_uint32();
            ts.tv_usec = (long) dis.read_uint32();
            incl_len = dis.read_uint32();
            orig_len = dis.read_uint32();
        }

        public void write_stream(DataOutputStream dos) {
            dos.put_uint32((uint32) ts.tv_sec);
            dos.put_uint32((uint32) ts.tv_usec);
            dos.put_uint32(incl_len);
            dos.put_uint32(orig_len);
        }


    }

    public const uint8 CWR = 0x0080;
    public const uint8 ECN = 0x0040;
    public const uint8 URG = 0x0020;
    public const uint8 ACK = 0x0010;
    public const uint8 PSH = 0x0008;
    public const uint8 RST = 0x0004;
    public const uint8 SYN = 0x0002;
    public const uint8 FIN = 0x0001;

    public class TCPFlags {
        public uint8 flags;

        public bool SYN { get { return (flags & NetFrames.SYN) == NetFrames.SYN; } }
        public bool ACK { get { return (flags & NetFrames.ACK) == NetFrames.ACK; } }
        public bool PSH { get { return (flags & NetFrames.PSH) == NetFrames.PSH; } }
        public bool RST { get { return (flags & NetFrames.RST) == NetFrames.RST; } }
        public bool FIN { get { return (flags & NetFrames.FIN) == NetFrames.FIN; } }
        public bool URG { get { return (flags & NetFrames.URG) == NetFrames.URG; } }

        public TCPFlags(uint8 value) {
            flags = value;
        }

        public string to_string() {
            string r = "";

            if (SYN) r = "SYN ";
            if (FIN) r = r + "FIN ";
            if (PSH) r = r + "PSH ";
            if (ACK) r = r + "ACK ";
            if (RST) r = r + "RST ";

            return r;
        }

        public bool equal(TCPFlags f) {
            return flags == f.flags;
        }
    }

bool is_ethernet(string s) {
    return (s.index_of(":") != -1);
}

ulong size_eth_ip_tcp() {
    return EtherHeader.size() + IPHeader.size() + TCPHeader.size();
}


uint16 read_uint16_buffer(uint8[] pkt, ref int cursor) {
    uint16 tmp = 0;
    Memory.copy(&tmp, &pkt[cursor], sizeof(uint16));
    cursor += (int) sizeof(uint16);
    return tmp;
}

uint32 read_uint32_buffer(uint8[] pkt, ref int cursor) {
    uint32 tmp = 0;
    Memory.copy(&tmp, &pkt[cursor], sizeof(uint32));
    cursor += (int) sizeof(uint32);
    return tmp;
}


uint8[] convert_uint32_into_uint8(uint32 value) {
    uint8[] result = new uint8[4];

    result[0] = (uint8) (value);
    result[1] = (uint8) (value >> 8);
    result[2] = (uint8) (value >> 16);
    result[3] = (uint8) (value >> 24);

    return result;
}

public void hexdump(uint8[] buffer, uint32 len, int largeur=16)
{
    int i = 0;
    int col = 0;
    string h = "";
    string s = "";

    for (i=0; i < len; i++) {
        // stdout.printf("%02X ", buffer[i], (char) buffer[i]);
        h = h + "%02X ".printf(buffer[i]);

        char tmp = (char) buffer[i];
        if (tmp.isprint())
            s = s + "%c" .printf ((char) buffer[i]);
        else
            s = s + ".";

        col++;
        if (col > largeur - 1) {
            col = 0;
            stdout.printf ("%s  %s\n", h, s);
            h = "";
            s = "";
        }
    }

    string toto = string.nfill (largeur * 3 - h.length, ' ');
    stdout.printf ("%s%s  %s\n", h, toto, s);
}

string to_binary(uint x, int len = 16) {
    uchar[] b = new uchar[len + 1];

    for (int z = 0; z < len; z++) {
        if (((x >> z) & 0x1) == 1)
            b[(len - 1)-z] = '1';
        else
            b[(len - 1)-z]= '0';
    }

    return (string) b;
}


string[] strip_tshark_line(string s) {
    string[] frame = {};
    string[] frame7 = {};
    string result = "";

    try {
        var regex = new Regex (" {2,}");
         result = regex.replace (s, -1, 0, " ");
         result = result.strip();
    } catch (RegexError e) {
        warning ("%s", e.message);
    }

    frame = result.split (" ", 8);

    if ((frame[7] != null) && (frame[7].index_of (">") != -1)) {
        frame7 = frame[7].split (" ", 4);
        frame.resize(frame.length + frame7.length - 1);

        int i = 7;
        foreach (unowned string str in frame7) {
            frame[i++] = str;
        }

    }

    return frame;
}



public string frame_to_string(Session s, Frame f) {
    return "(num: %d) %s %s %s seq:%d ack:%d len:%d  %s".printf (
        (int) f.num, s.first_frame_host.to_string(),
        (f.src.equal(s.first_frame_host.addr) ? "-->" : "<--"),
        s.second_frame_host.to_string(),
        (int) f.rel_seq, (int) f.rel_ack, (int) f.len,
        f.tcp_flags.to_string()
        );
}

}
