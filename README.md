Libnetframes
============

Classes to handle frames from a pcap file in different ways.

Using sorted_list (Copyright 2009-2013 Yorba Foundation)

Capture
-------
Global class which store hosts, connections and frames.

You can :
	- open a pcap file
		public Capture (string filename, bool shark_decode = true);
		public Capture.from_tshark (string filename);

		==> a structure is build to store :
			- hosts list
			- frames list
			- connections list which contain connection host to host
				each connection contain
					Sessions list which session host:port to host:port

		Example : 			
			Capture c = new Capture("test.pcap");

		Note: If you have Wireshark in your PATH variable, tshark should be spwaned 
		to get more informations about frames.

	- save a pcap file
		public void save_pcap (string uri);

	- remove an object
		public void delete_connection (NetFrames.Connection c);
		public void delete_host (GLib.InetAddress host);
		public void delete_session (NetFrames.Session s);


Hosts
-----
	- test if an IP address is present
		public new bool contains (GLib.InetAddress addr);

		Example : 
			c.hosts.contains (new GlibInetAddress.from_string("192.168.0.1"));

Connections
-----------
	Connections contains all connection relative to "host to host"

	Example :
		foreach (Connection conn in c.connections)
			conn.display();

	Search a connection
		public NetFrames.Connection search_connection (NetFrames.Connection to_search);

	Connection
	----------
		- test if a connection has a specific host
			public bool has_host (GLib.InetAddress host);

		- test if a connection is equal to this connection
			public bool is_equal (NetFrames.Connection c);

Sessions
--------
	Sessions contains all sessions relative to "host:port to host:port"

	- get all sessions relative to a connection

		Example :
			foreach (Session s in conn.sessions)
				s.display();

Frames
------

	- get info from tshark decoding
		public string dissect;

	- get info 
		public uint32 num;
		public string proto;
		public GLib.TimveVal time;
		public GLib.InetAddress dst;
		public uint16 dst_port;
		public GLib.InetAddress src;
		public uint16 src_port;
		public uint32 len,

	- get a connection or a session from frames
		public NetFrames.Connection connection;
		public NetFrames.Session session;

	- test if this frame contains a host
		public bool has_host (GLib.InetAddress host);


