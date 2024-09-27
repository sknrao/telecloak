#!/usr/bin/env python

# Copyright (c) 2007-2008, Universita' di Brescia, ITALY
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY Universita' di Brescia ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <copyright holder> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Original author: Ettore Bonazzoli
# Further revisions by Luca Salgarelli <luca.salgarelli@ing.unibs.it>
#


"""
This module provides the functionality of stream reassembly.

The input SHOULD be a pcap dump file relative to just one stream:
alternatively it's up to the user to pass the correct pcap_filter
string in order to filter out the one stream needed.

In addition the program can be launched as a command line utility.
"""

import os, sys
import dpkt

# a note:
# dpkt 1.4 surely works but has a different syntax:
# Reader --> PcapReader
# Writer --> PcapDumper (which don't need filelike objects as input)
# Writer.writepkt --> PcapDumper.append
if dpkt.__version__ != '1.6':
    print('dpkt library MUST be version 1.6: current is', dpkt.__version__, '\n')
    #sys.exit()

def log_data(write_dir, data, src, sport, dst, dport, counter=-1):
    """
    log_data(write_dir, data, src, sport, dst, dport)
    
    This function logs out data into files when the module
    is working as command line utility.
    """
    
    if counter >= 0:
        # alignment
        zeros = 5
        filename = "%s/%0*d_%s.%s-%s.%s" % (write_dir, zeros, counter, src, sport, dst, dport)
    else:
        filename = "%s/%s.%s-%s.%s" % (write_dir, src, sport, dst, dport)
    
    try:
        f = open(filename, 'w')
        f.write(data)
    finally:
        f.close()


def tcp_todo(half_stream_data, verbose):
    """
    tcp_todo(half_stream_data, verbose)
    
    half_stream_data: list of tuples (seq, data, SYN, FIN)
    """
    
    half_stream_data.sort()
    awaited_seq = 0
    collected_data = str()
    
    for seq, data, SYN, FIN in half_stream_data:
        if SYN:
            awaited_seq = seq + 1
        else:
            # the right fragment
            if seq == awaited_seq:
                collected_data += data
                awaited_seq += len(data)
                if FIN:
                    awaited_seq += 1
            elif seq < awaited_seq:
                # check out if it carries new data anyway
                seq_after_this = seq + len(data)
                new_data = seq - seq_after_this
                if new_data < 0: # we have something
                    collected_data += data[new_data:]
                    awaited_seq = seq_after_this
            else:
                if verbose:
                    print("Data lost")
    
    return collected_data


def tcp_reassembly(source_dump_file, pcap_filter=None, log=False, verbose=False):
    """
    tcp_reassembly(source_dump_file[, pcap_filter])
    
    pcap_filter : data input filter in tcpdump format
        for example pcap_filter = "tcp and port 80"
    
    This function sets up the tcp reassembly task.
    """
    
    try:
        f_filelike = open(source_dump_file)
        f = dpkt.pcap.Reader(f_filelike)
    except:
        print("an error has occurred with %s" % source_dump_file)
        raise 
    
    if pcap_filter:
        f.setfilter(pcap_filter)
    
##    dport = 0 #no need..
    client_frames = list()
    server_frames = list()
    
    counter = 0
    for ts, pkt in f:
        counter += 1
        eth = dpkt.ethernet.Ethernet(pkt)
        # to ease things
        tcp = eth.ip.tcp
        # to set direction and logout names
        if counter == 1:
            dport = tcp.dport
            sport = tcp.sport
            src = dpkt.dnet.ip_ntoa(eth.ip.src)
            dst = dpkt.dnet.ip_ntoa(eth.ip.dst)
        # store data in tuple (seq, data, SYN, FIN)
        if tcp.dport == dport:
            # client side
            client_frames.append((tcp.seq, tcp.data, tcp.flags & 2, tcp.flags & 1))
        elif tcp.sport == dport:
            server_frames.append((tcp.seq, tcp.data, tcp.flags & 2, tcp.flags & 1))
        else:
            print("Something wrong: maybe your pcap_filter is not correct")
    
    f_filelike.close()
    
    cli_data = tcp_todo(client_frames, verbose)
    srv_data = tcp_todo(server_frames, verbose)
    if log:
        log_data(clopts.write_dir, cli_data, src, sport, dst, dport)
        log_data(clopts.write_dir, srv_data, dst, dport, src, sport)
    else:
        return cli_data, srv_data


if __name__ == '__main__':
    
    from optparse import OptionParser
    
    usage = "usage: %prog [options] infile"
    
    oparser = OptionParser(usage = usage)
    
    oparser.add_option("-d","--write-dir", help="output directory (default: streamdata)", dest="write_dir")
    oparser.add_option("--pcap-filter", help='pcap read filter (default: None)', dest="pcap_filter")
    oparser.add_option("-v", "--verbose", dest="verbose")
    
    oparser.set_defaults(write_dir="streamdata", pcap_filter=None, verbose=False)
    
    [clopts, infile] = oparser.parse_args()
    
    if not infile:
        oparser.error("No arguments given, see --help option")
    elif len(infile) > 1:
        oparser.error("Too many arguments given, see --help option")
    
    # check out if write_dir exists and is accessible or not
    if not os.access(clopts.write_dir, os.F_OK):
        try:
            os.mkdir(clopts.write_dir)
        except:
            e = "Error while creating write directory %s" % clopts.write_dir
            raise IOError(e)
    elif not os.access(clopts.write_dir, os.R_OK | os.W_OK):
        e = "Error while checking permissions on write directory %s" % clopts.write_dir
        raise IOError(e)
    
    tcp_reassembly(infile[0], clopts.pcap_filter, True, clopts.verbose)
    
