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
This program is a TCP trace anonymizer.
Referring to the TCP/IP stack, what's new is the capability
to work at level 7 that is the TCP stream is first interpreted
in order to reassembly PDUs and then only sensible data
according to the application is intended to be camouflaged.
So far it works with the most common "clear text" protocols:
HTTP, SMTP, POP3, IMAP4, FTP, FTP-data.
"""

import os, sys, tempfile, shutil
from optparse import OptionParser

try:
    import dpkt
except ImportError:
    print("Error: could not load the 'dpkt' library. Please download it from\n\
    http://code.google.com/p/dpkt/\n\
and install it before running this program")
    sys.exit(255)

import struct
import datetime

# a note:
# dpkt 1.4 surely works but has a different syntax:
# Reader --> PcapReader
# Writer --> PcapDumper (which don't need filelike objects as input)
# Writer.writepkt --> PcapDumper.append
if dpkt.__version__ != '1.6':
    print('dpkt library MUST be version 1.6: current is', dpkt.__version__, '\n')
    #sys.exit()

# local stuff
from fcap import fcap
from tcp_reassembly import tcp_reassembly, log_data
from ftp  import process_ftp
from smtp import process_smtp
from http import process_http
from pop3 import process_pop3
from imap4r1 import process_imap4

from xml.dom import minidom as Xp

STAGE1 = 'flow analysis'
STAGE2 = 'XML parsing'
STAGE3 = 'source dumpfile slicing'
STAGE4 = 'TCP stream reassembly'
STAGE5 = 'stream anonymization'
STAGE6 = 'sorting and merging'

SNAPLEN = 65535
RIENTRO_SX = '\n' + 2 * '\t'
RIENTRO_DX = 2* '\n'
zeros = 5

class flow_object:
    """
    We construct python objects to work with after parsing XML report.
    
    A flow object has several attributes:
        src         : source ip address (i.e. client)
        dst         : destination ip address (i.e. server)
        sport       : source port
        dport       : destination port
        flow_number : numerical identifier
        start_time  : timestamp of the first packet
        end_time    : timestamp of the last packet
        packets     : list of packets number composing the flow
        analyzed    : True/False flag
        
    Recording start_time and end_time it's useful while processing nested flows.
    """
    
    def __init__(self, xml_flow, counter):
        self.src = str(xml_flow.getElementsByTagName("src")[0].firstChild.data)
        self.dst = str(xml_flow.getElementsByTagName("dst")[0].firstChild.data)
        self.sport = int(xml_flow.getElementsByTagName("sport")[0].firstChild.data)
        self.dport = int(xml_flow.getElementsByTagName("dport")[0].firstChild.data)
        self.flow_number = counter
        self.start_time = float(xml_flow.getElementsByTagName("start_time")[0].firstChild.data)
        self.end_time = float(xml_flow.getElementsByTagName("end_time")[0].firstChild.data)
        packets = xml_flow.getElementsByTagName("packets")[0].firstChild.data.strip('[]')
        self.packets = list(map(int, packets.split(',')))
        self.analyzed = False


def find_ftp_data_streams(all_flows_obj, curr_flow, host, port):
    """
    find_ftp_data_streams(all_flows_obj, curr_flow, host, port)
    
    all_flows_obj   : flow objects to scan through
    curr_flow       : command connection flow_object
    host            : data connection host
    port            : data connection port
    
    This function looks for ftp-data connections which fit a command connection.
    It returns a list of such objects.
    """
    
    # host,port direction
    if host == curr_flow.dst:
        client_side = True
    else:
        client_side = False
    
    to_process = list()
    
    # pick out the flow(s)
    for flow in all_flows_obj:
        if (not flow.analyzed) and flow.start_time > curr_flow.start_time\
                               and flow.end_time < curr_flow.end_time:
            if (client_side and flow.dport == port and flow.dst == host) or\
                ((not client_side) and flow.sport == port and flow.src == host):
                    to_process.append(flow)
    
    return to_process
    
def hide_or_discard_tcp_data(pkt, keepsize=False):    
    """
    anonpkt = hide_or_discard_tcp_data(pkt, keepsize=False)
    
    pkt         : packet in pcap format
    keepsize    : when False tcp data is to be discarded,
                  when True tcp data is to be hidden keeping size.
                  
    This function discards or replaces, with zeros, tcp data from packets
    returning the new packet after adjusting the checksum.
    """
    
    eth = dpkt.ethernet.Ethernet(pkt)
    
    # if there's data then do anonymize
    if eth.ip.tcp.data:
        if keepsize:
            eth.ip.tcp.data = '0' * (len(eth.ip.tcp.data) - 2)
            eth.ip.tcp.data += '\r\n' # would you like to read a never ending line of zeros??
        else:
            eth.ip.tcp.data = ''
        
        # do_checksum
        eth.ip.tcp.sum = 0
        pseudo_hdr = eth.ip.src + eth.ip.dst + struct.pack("!H", 6) +\
            struct.pack("!H", len(eth.ip.data))
        eth.ip.tcp.sum = dpkt.in_cksum(pseudo_hdr + eth.ip.tcp.pack())
        
        return eth.pack()
    else:
        # connection stuff
        return pkt


def anon_flow(in_filename, out_obj, bcli, bsrv, acli, asrv):
    """
    anon_flow(in_filename, out_obj, bcli, bsrv, acli, asrv)
    
    in_filename : input pcap filename
    out_obj     : already opened pcap dump file
    bcli        : original client data
    bsrv        : original server data
    acli        : anonymized client data
    asrv        : anonymized client data
    
    This functions performs the sostitution of data into the packets.
    
    NOTE:
        bcli, bsrv, acli, asrv carry in tcp data:
            - b stands for before processing
            - a stands for after processing
            - cli and srv of course stand for client/server side
    """
    
    src_filelike = open(in_filename, 'rb')
    src = dpkt.pcap.Reader(src_filelike)
    
    for ts, pkt in src:
        eth = dpkt.ethernet.Ethernet(pkt)
        # if there's data then do anonymize
        if eth.ip.tcp.data:
            do_checksum = False
            # to ease things
            srvfound = bsrv.find(eth.ip.tcp.data)
            clifound = bcli.find(eth.ip.tcp.data)
            # don't care about repetitions
            # same input --> same output (most likely!)
            if srvfound != -1:
                eth.ip.tcp.data = asrv[srvfound:srvfound + len(eth.ip.tcp.data)]
                do_checksum = True
            elif clifound != -1:
                eth.ip.tcp.data = acli[clifound:clifound + len(eth.ip.tcp.data)]
                do_checksum = True
            
            # checksum
            if do_checksum:
                eth.ip.tcp.sum = 0
                pseudo_hdr = eth.ip.src + eth.ip.dst + struct.pack("!H", 6) +\
                    struct.pack("!H", len(eth.ip.data))
                eth.ip.tcp.sum = dpkt.in_cksum(pseudo_hdr + eth.ip.tcp.pack())
            
            anonpkt = eth.pack()
        else:
            # connection stuff
            anonpkt = pkt
        # finally dump the packet
        out_obj.writepkt(anonpkt, ts)
            
    src_filelike.close()


def main():
    """
    This is the main corp of tcpanon.
    We like to divide it in 3 parts:
        a. initial stuff (basically parameters setting)
        b. main program
        c. final stuff (close files, handle tmpdata and so)
        
    Step by step the main program (part b.) goes through:
        1. flow analysis
        2. XML parsing
        3. source dumpfile slicing
        4. TCP stream reassembly
        5. stream anonymization
        6. sorting and merging
    and all in all each stage is thought with modularity in mind.
    """
    
    usage = "usage: %prog [options] infile"
    
    oparser = OptionParser(usage=usage)
    
    oparser.add_option('-t','--tmp-dir', help='path to temp directory', dest='tmpdir')
    oparser.add_option('--no-del-tmp', help='keep temp files for debugging purposes',\
        dest='nodeltmp', action='store_true')
    oparser.add_option('-o', '--output-file', help='default: "infile".anon', dest='outfile')
    oparser.add_option('-p', '--protocols', help='a comma separated list of ports. default: 21,25,80,110,143',\
        dest="protocols")
    oparser.add_option('-N', '--not-protocols', help='a comma separated list of ports. default: None',\
        dest="notprotocols")
    oparser.add_option('--ftpdata', help='keep ftpdata size independently of -U option',\
        dest='processftpdata', action='store_true')
    oparser.add_option('--show-XML', help='show XML flow analysis', dest='showXML', action='store_true')
    oparser.add_option('-c', '--config-file', help='default: "tcpanon.config"', dest='cfgfile')
    oparser.add_option('-U','--keep-unchanged', help='keep untrained protocol tcp data unchanged',\
        dest='unchanged', action='store_true')
    oparser.add_option('-S','--keep-size', help='hide untrained protocol tcp data keeping size',\
        dest='keepsize', action='store_true')
    oparser.add_option('-M','--max-files', help='max open files at the same time. default: 250',\
        dest='maxfiles', type='int')
    oparser.add_option('-v','--verbose', help='displays when entering the tasks',\
        dest='verbose', action='count')
    
    oparser.set_defaults(tmpdir=None, nodeltmp=False, outfile=None, protocols=None, notprotocols=None,\
        processftpdata=False, showXML=False, cfgfile='tcpanon.config', unchanged=False, keepsize=False,\
        maxfiles=250, verbose=0)
    
    [clopts, infile] = oparser.parse_args()
    
    # check there's 1 and only 1 infile
    if not infile:
        oparser.error("No arguments given, see --help option")
    elif len(infile) > 1:
        oparser.error("Too many arguments given, see --help option")
    else:
        infile = infile[0]
    
    if not os.path.isfile(infile):
        print("infile not present or bad file")
        sys.exit()
    # check infile and datalink layer
    try:
        f = open(infile, 'rb')
        if dpkt.pcap.Reader(f).datalink() != 1:
            e = "Sorry, the datalink layer is not Ethernet"
            raise TypeError(e)
    except TypeError:
        raise
    #except Exception:
    #    print("infile not present or bad file")
    f.close()
    
    # check protocols
    real_implemented_protocols = (21, 25, 80, 110, 143)
    if not clopts.protocols  and not clopts.notprotocols:
        implemented_protocols = real_implemented_protocols
    else:
        try:
            if clopts.protocols:
                protocols_set = set(map(int, clopts.protocols.split(',')))
            else:
                protocols_set = set(real_implemented_protocols)
            if clopts.notprotocols:
                not_protocols_set = set(map(int, clopts.notprotocols.split(',')))
            else:
                not_protocols_set = set([])
            implemented_protocols = protocols_set - not_protocols_set
            
            if not implemented_protocols:
                raise LookupError("Well folks: no protocols, it seems nothing to do..!")
            else:
                for proto in implemented_protocols:
                    if not proto in real_implemented_protocols:
                        raise LookupError("Sorry, %s not implemented..yet!" % proto)
        except LookupError:
            raise
        except ValueError:
            oparser.error("the argument of '-p' or '-N' MUST be a string of comma separated integers")
        except:
            raise
            
    if clopts.processftpdata and not 21 in implemented_protocols:
            oparser.error("you can't process ftp-data without processing ftp sessions!")
    
    if clopts.processftpdata and clopts.keepsize:
            print("\n\t--ftpdata makes nonsense while -S is set: ignoring..\n")
    
    if clopts.maxfiles <1 :
            oparser.error("max-files MUST be > 1!")
            
    # check if we've got a temp dir
    try:
        # we should care about removing it at the end
        tmpdir = tempfile.mkdtemp(dir = clopts.tmpdir)
    except:
        raise IOError("No writable temp directory found: see -t option.")
    
    if clopts.outfile == None:
        clopts.outfile = os.path.basename(infile) + ".anon"

    if clopts.keepsize and clopts.unchanged:
        oparser.error("options -S and -U are mutually exclusive")

    try:
        # --------<main program>-----------------------------------------
        # --stage 1 : flow analysis
        if clopts.verbose:
            t1 = datetime.datetime.now()
            print("%s\n\tEntering stage1: %s" % (t1.ctime(), STAGE1))
        
        # sucker_out.xml
        flow_analysis = fcap(infile)
        flow_analysis.run()
        xml_out = flow_analysis.xml_report()
        all_source_read_packets = flow_analysis._all_read_packets
        
        if clopts.showXML:
            print(xml_out)
        
        # --stage 2 : XML parsing
        # of course scanning the connection database itself allows to work without XML data,
        # anyway our choice this way.. thus we can display it out with --show-XML for any purpose
        
        if clopts.verbose:
            t2 = datetime.datetime.now()
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t2 - t1, RIENTRO_DX))
            print("%s\n\tEntering stage2: %s" % (t2.ctime(), STAGE2))
        
        all_flows_obj = list()
        
        try:
            xml_report = Xp.parseString(xml_out)
        except xml.parsers.expat.ExpatError:
            print("Something wrong with flow analysis or its XML report.")
            raise
            
        xml_flows = xml_report.getElementsByTagName('flow')
        
        for idx, elem in enumerate(xml_flows):
            all_flows_obj.append(flow_object(elem, idx + 1))
        
        # --stage 3 : source dumpfile slicing
        if clopts.verbose:
            t3 = datetime.datetime.now()
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t3 - t2, RIENTRO_DX))
            print("%s\n\tEntering stage3: %s" % (t3.ctime(), STAGE3))
        
        pcap_dir = tmpdir + '/pcap'
        pcap_dir_slash = pcap_dir + '/'
        os.mkdir(pcap_dir)
        
        # open unsorted_out (final data, not in order though)
        unsorted_out = pcap_dir_slash + 'unsorted_out'
        uo_file = open(unsorted_out, 'wb')
        uo = dpkt.pcap.Writer(uo_file, SNAPLEN)
        
        # if infile is very big and most likely it has a lot of simultaneous connections
        # the number of open files could be a problem: 
        # open and close file-like objects costs a lot of time..
        # if we can open as many files as we want, then the slicing
        # is achieved in a shot "spreading" packets after opening
        # infile just one time
        # so.. tuning -M could be a right thing to do
        
        # packet dictionary to lookup flows
        packet_dict = dict()
        for flow in all_flows_obj:
            if flow.dport in implemented_protocols:
                for idx in flow.packets:
                    packet_dict[idx] = flow.flow_number

        # to close files (descriptors)
        extracted_dict = dict()
        for flow in all_flows_obj:
            extracted_dict[flow.flow_number] = 0
        
        END = False
        open_files = 0
        extracted_list = list()
        open_list = list()
        jumped_list = list()
        
        while not END:
            f_filelike = open(infile,'rb')
            f = dpkt.pcap.Reader(f_filelike)
            index = 0
            
            for ts, pkt in f:
                index += 1
                # flow lookup
                try:
                    which_flow = packet_dict[index]
                # if not found then next (basically non TCP packets)
                except KeyError:
                    continue
                
                if which_flow in (extracted_list or jumped_list):
                    continue
                
                filename = pcap_dir_slash + "%0*d" % (zeros, which_flow)
                objectname = 'o' + str(which_flow)
                
                if which_flow not in open_list:
                    # Can we open it in regard of max-files?
                    if open_files < clopts.maxfiles:
                        exec('%s_filelike = open("%s", "w")' % (objectname, filename))
                        exec('%s = dpkt.pcap.Writer(%s_filelike, SNAPLEN)' % (objectname, objectname))
                        open_files += 1
                        open_list.append(which_flow)
                    #if not --> next round
                    else:
                        if which_flow not in jumped_list:
                            jumped_list.append(which_flow)
                        continue
                
                # now we have to write the packet and eventually "close" the flow
                try:
                    exec('%s.writepkt(pkt, ts)' % objectname)
                    extracted_dict[which_flow] += 1
                    if extracted_dict[which_flow] == len(all_flows_obj[which_flow - 1].packets):
                        exec('%s.close()' % objectname)
                        open_list.remove(which_flow)
                        extracted_list.append(which_flow)
                        open_files -= 1
                except:
                    raise
            else:
                f_filelike.close()
                if not jumped_list:
                    END = True
                else:
                    if clopts.verbose > 2:
                        print("ho saltato %s\n" % jumped_list)
                    jumped_list = list()
            
        
        # --stage 4 : TCP stream reassembly
        if clopts.verbose:
            t4 = datetime.datetime.now()
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t4 - t3, RIENTRO_DX))
            print("%s\n\tEntering stage4: %s" % (t4.ctime(), STAGE4))
            
        # verbosity level 2 --> reassembly info 
        if clopts.verbose > 1:
            processing_verbosity = True
        else:
            processing_verbosity = False
        
        for flow in all_flows_obj:
            if flow.dport in implemented_protocols:
                cli_data, srv_data = tcp_reassembly(pcap_dir_slash + "%0*d" % (zeros, flow.flow_number),\
                    verbose=processing_verbosity)
                log_data(tmpdir, cli_data, flow.src, flow.sport, flow.dst, flow.dport, flow.flow_number)
                log_data(tmpdir, srv_data, flow.dst, flow.dport, flow.src, flow.sport, flow.flow_number)
        
        
        # --stage 5 : stream anonymization
        if clopts.verbose:
            t5 = datetime.datetime.now()
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t5 - t4, RIENTRO_DX))
            print("%s\n\tEntering stage5: %s" % (t5.ctime(), STAGE5))
            
        ftpdata_streams = list()
    
        for flow in all_flows_obj:
            if not flow.analyzed:
                # if implemented then anonymize
                if flow.dport in implemented_protocols:
                    client_filename = "%s/%0*d_%s.%s-%s.%s" % (tmpdir, zeros, flow.flow_number, \
                    flow.src, flow.sport, flow.dst, flow.dport)
                    server_filename = "%s/%0*d_%s.%s-%s.%s" % (tmpdir, zeros, flow.flow_number, \
                    flow.dst, flow.dport, flow.src, flow.sport)
                    try:
                        fc = open(client_filename)
                        fs = open(server_filename)
                        bcli = fc.read()
                        bsrv = fs.read()
                    finally:
                        fc.close()
                        fs.close()
                    if flow.dport == 21:
                        acli, ftp_data_1 = process_ftp(bcli)
                        asrv, ftp_data_2 = process_ftp(bsrv)
                        # find out data streams.. only if -S is not set
                        if (not clopts.keepsize) and clopts.processftpdata:
                            for host, port in ftp_data_1 + ftp_data_2:
                                ftpdata_streams += find_ftp_data_streams(all_flows_obj, flow, host, port)
                            
                    elif flow.dport == 25:
                        acli = process_smtp(bcli)
                        asrv = process_smtp(bsrv)
                    elif flow.dport == 80:
                        acli = process_http(bcli, clopts.cfgfile, processing_verbosity)
                        asrv = process_http(bsrv, clopts.cfgfile, processing_verbosity)
                    elif flow.dport == 110:
                        acli = process_pop3(bcli)
                        asrv = process_pop3(bsrv)
                    elif flow.dport == 143:
                        acli = process_imap4(bcli)
                        asrv = process_imap4(bsrv)
                    anon_flow(pcap_dir_slash + "%0*d" % (zeros, flow.flow_number), uo, bcli, bsrv, acli, asrv)
                    flow.analyzed = True

        uo.close()
        
        # let's have a look at all the packets
        # dividing them into three sets
        # 1. the anonymized ones
        # 2. ftp-data if need be
        # 3. the other tcp packets
        
        # this is basically to keep the capability to handle non tcp data
        # but also to write out unchanged packets (-U option)
        
        # process ftp-data has been thought as a stand-alone task
        # because could be of some interest keeping its size
        # while discarding all the rest.. it's like -S but only for this data
        # of course it makes sense only if -S is not set
        
        all_processed_packets_set = set()
        all_ftp_data_packets_set = set()
        all_not_processed_tcp_packets_set = set()
        for flow in all_flows_obj:
            if flow in ftpdata_streams:
                all_ftp_data_packets_set = all_ftp_data_packets_set.union(set(flow.packets))
                continue
            if flow.analyzed:
                all_processed_packets_set = all_processed_packets_set.union(set(flow.packets))
                continue
            all_not_processed_tcp_packets_set = all_not_processed_tcp_packets_set.union(set(flow.packets))
        
        
        # --stage 6 : sorting and merging
        if clopts.verbose:
            t6 = datetime.datetime.now()
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t6 - t5, RIENTRO_DX))
            print("%s\n\tEntering stage6: %s" % (t6.ctime(), STAGE6))
        
        # sorting a big file with a huge number of packets could be an ordeal
        # and it certanly costs a lot of time even with a good algorithm
        # whose complexity is O(n log(n)).. so the idea is very simple:
        # do not sort what is already sorted
        
        # now we have 2 input files:
        # 1. unsorted_out, containing all processed packets (shuffled)
        # 2. infile, containing ALL
        # so we're gonna keep everything unchanged from infile
        # while applying changes from unsorted_out
        
        # to keep the sorting light we split up the payload
        unsorted_out_dict = dict()
        unsorted_packets = list()

        # if you're asking yourself why this data haven't been keept directly
        # in memory.. well to be able to "inspect" data with no-del-tmp
        f_filelike = open(unsorted_out,'rb')
        f = dpkt.pcap.Reader(f_filelike)
        index = 0
        for ts, pkt in f:
            index += 1
            unsorted_packets.append((ts, index))
            unsorted_out_dict[index] = str(pkt)

        f_filelike.close()
        unsorted_packets.sort()
        
        if clopts.verbose:
            t7 = datetime.datetime.now()
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t7 - t6, RIENTRO_DX))
            print("%s\n\tWriting..." % t7.ctime())
        
        # outdump directly from sources
        f_infile_filelike = open(infile,'rb')
        f_infile = dpkt.pcap.Reader(f_infile_filelike)
        
        outdump_file = open (clopts.outfile, 'wb')
        outdump = dpkt.pcap.Writer(outdump_file, SNAPLEN)
        
        index_infile = 0
        index_unsorted = 0 # well.. sorted by now :)
        
        # now we have these 3 sets:
        # 1. all_processed_packets_set
        # 2. all_ftp_data_packets_set
        # 3. all_not_processed_tcp_packets_set
        
        for ts, pkt in f_infile:
            index_infile += 1
            if index_infile in all_processed_packets_set:
                ts, key = unsorted_packets[index_unsorted]
                pkt = unsorted_out_dict[key]
                index_unsorted += 1
            elif index_infile in all_ftp_data_packets_set:
                pkt = hide_or_discard_tcp_data(pkt, True)
            elif not clopts.unchanged:
                if index_infile in all_not_processed_tcp_packets_set:
                    pkt = hide_or_discard_tcp_data(pkt, clopts.keepsize)
            
            outdump.writepkt(pkt, ts)
        
        f_infile_filelike.close()
        outdump.close()
        
        if clopts.verbose:
            t8 = datetime.datetime.now()
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t8 - t7, RIENTRO_DX))
            print("%s\n\tDone!" % t8.ctime())
            print("%sElapsed Time: %s%s" % (RIENTRO_SX, t8 - t1, RIENTRO_DX))
        
        # --------</main program>-----------------------------------------
    
    except KeyboardInterrupt:
        raise
    
    if clopts.nodeltmp:
        print("--no-del-tmp option found: you can find temporary data in\n%s" %tmpdir)
    else:
        # clear temp directory
        shutil.rmtree(tmpdir)

if __name__ == "__main__":
    main()
