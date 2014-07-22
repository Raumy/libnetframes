#  Makefile
#  
#  Copyright 2013-2014 Cyriac REMY <raum@no-log.org>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#

 
PROGRAM = libnetframes
GETTEXT_PACKAGE = libnetframes
VERSION = 0.1

GEE_WIN_VERSION=0.8
GEE_LINUX_VERSION=0.8
PCAP_WIN_LIB=wpcap
PCAP_LINUX_LIB=pcap

C_DEFINES := _VERSION='"$(VERSION)"' GETTEXT_PACKAGE='"$(GETTEXT_PACKAGE)"'	
DEFINE_CFLAGS := $(foreach def,$(C_DEFINES),-X -D$(def))

VALA_DEFINES := 
DEFINE_VALAFLAGS := $(foreach def,$(VALA_DEFINES),-D $(def))

DEFINE_FLAGS := $(DEFINE_CFLAGS) $(DEFINE_VALAFLAGS)

# packages used 
PKGS_WIN =  --pkg gee-$(GEE_WIN_VERSION) --pkg gio-2.0 --pkg libpcap
PKGS_LINUX = --pkg gee-$(GEE_LINUX_VERSION) --pkg gio-2.0 --pkg libpcap
	
# source files
SRC = src/captures.vala \
	src/frames.vala \
	src/hosts.vala \
	src/connections.vala \
	src/sessions.vala \
	src/structs.vala \
	src/tcp_flow.vala \
	src/sorted_list.vala

# vala compiler
VALAC = valac
 
# compiler options for a standard build
# preprocessor variables :
#    WINDOWS : compilation on MingW32/Windows
#    LINUX : compilation on Linux distribution
#    TSHARK_DECODE_ENABLED : compile with tshark spawn support
#VALACOPTS = -D WINDOWS -X -w --disable-warnings -X -I/opt/include -X -lwpcap

VALA_WIN_COPTS = --library=lib/$(PROGRAM) -H lib/$(PROGRAM).h -g -X -w --disable-warnings -X -I/opt/include -X -l$(PCAP_WIN_LIB) --target-glib=2.32 -X -fPIC -X -shared 
VALA_LINUX_COPTS = --library=lib/$(PROGRAM) -H lib/$(PROGRAM).h -g -X -w --disable-warnings -X -I/opt/include -X -l$(PCAP_LINUX_LIB) --target-glib=2.32 -X -fPIC -X -shared 

# the 'all' target build a debug build
	#@$(VALAC) $(VALA_WIN_COPTS) $(DEFINE_FLAGS) $(SRC) $(SRC_LIB) -o npc-win/$(PROGRAM) $(PKGS_WIN)

windows:
	@$(VALAC) $(VALA_WIN_COPTS) $(SRC) -o lib/$(PROGRAM).dll $(PKGS_WIN)
	cp lib/* examples/
	
linux:
	@$(VALAC) $(VALA_LINUX_COPTS) $(SRC) -o lib/$(PROGRAM).so $(PKGS_LINUX)
# 	@$(VALAC) $(PKGS_WIN) $(VALA_WIN_COPTS) $(DEFINE_FLAGS) $(SRC) -o $(PROGRAM).so
