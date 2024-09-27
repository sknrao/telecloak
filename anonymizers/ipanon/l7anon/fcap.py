#!/usr/bin/python

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
# Original author: Francesco Gringoli <francesco.gringoli@ing.unibs.it>
#

#global idx_DB
import sys

try:
    import dpkt
except ImportError:
    print("Error: could not load the 'dpkt' library. Please download it from\n\
    http://code.google.com/p/dpkt/\n\
and install it before running this program")
    sys.exit(255)

try:
    import dnet
except ImportError:
    print("Error: could not load the 'dnet' library. Please download it from\n\
    http://code.google.com/p/libdnet/\n\
and install it before running this program")
    sys.exit(255)

#from binascii import hexlify, unhexlify
from time import time

#-------------------------------------------------------------------------------
class Flow:
    idx=0
    def __init__(self,tiippkt_):
        ippkt_=tiippkt_[1]
        self.srcadd=ippkt_.src
        self.dstadd=ippkt_.dst
        self.srcport=ippkt_.data.sport
        self.dstport=ippkt_.data.dport
        self.start_time=0
        self.end_time=0
        self._status=0
        self._dir="fclient"
        self._time0=time()
        #self._sess=session.session()
        self._finished=0
        self._log={"fclient":[],"fserver":[]}
        self._pkts=[]
        self._curpkt=tiippkt_
	    # update of flow ID
        self._idx=Flow.idx
        Flow.idx=Flow.idx+1
        self._curl2pkt=None
    def setcurl2pkt(self,curl2pkt):
	    self._curl2pkt=curl2pkt
    def getcurl2pkt(self):
	    (ts, pkt)=self._curl2pkt
	    #outstr=str(pkt)
	    #outstr+=hexlify(pkt)
	    return(ts,str(pkt))
    def flow2str(self):
        ipsrc_=dnet.ip_ntoa(self.srcadd)
        ipdst_=dnet.ip_ntoa(self.dstadd)
        ports_='%d %d' % (self.srcport,self.dstport)
        str=ipsrc_+' '+ipdst_+' '+ports_
        return str
    def logmsg(self,str_):
        msg_=self.flow2str()+' '+str_+'\n'
        sys.stdout.write(msg_)
    def setstatus(self,status_):
        self._status=status_
    def getstatus(self):
        return self._status
    def setdir(self,dir_):
        self._dir=dir_
    def getdir(self):
        return self._dir
    def setfin(self,dir_):
        self._fin=dir_
    def getfin(self):
        return self._fin
    def isfclient(self):
        return self._dir=="fclient"
    def isfserver(self):
        return self._dir=="fserver"
    def isfinished(self):
        return self._finished
    def setcurpkt(self,tiippkt_):
        self._curpkt=tiippkt_
    def log(self,obj=None):
        # add to the log list the passed object
        self._log[self._dir].append(obj)
#-------------------------------------------------------------------------------
class TrackDB(dict):

    def __init__(self):
        dict.__init__(self)
#-------------------------------------------------------------------------------
#    def crearamo(self,tiippkt_,pkt_idx):
    def crearamo(self,tiippkt_):

        flow=Flow(tiippkt_)
#        flow._pkts.append(pkt_idx)
        ippkt_=tiippkt_[1]
        if ippkt_.src not in self:
            self[ippkt_.src]={}
        if ippkt_.dst not in self[ippkt_.src]:
            self[ippkt_.src][ippkt_.dst]={}
        if ippkt_.data.sport not in self[ippkt_.src][ippkt_.dst]:
            self[ippkt_.src][ippkt_.dst][ippkt_.data.sport]={}
        if ippkt_.data.dport not in self[ippkt_.src][ippkt_.dst][ippkt_.data.sport]:
            self[ippkt_.src][ippkt_.dst][ippkt_.data.sport][ippkt_.data.dport]=flow
	
        return flow
#-------------------------------------------------------------------------------
    def togliramo(self,flow_):
        # sicuramente tutte le foglie del ramo "flusso" esistono
        dstaddlist_=self[flow_.srcadd]
        srcportlist_=dstaddlist_[flow_.dstadd]
        dstportlist_=srcportlist_[flow_.srcport]
        # cancello lista con i dettagli di QUESTA connessione
        del dstportlist_[flow_.dstport]
        if len(dstportlist_) > 0:
            return
        del srcportlist_[flow_.srcport]
        if len(srcportlist_) > 0:
            return
        del dstaddlist_[flow_.dstadd]
        if len(dstaddlist_) > 0:
            return
        del self[flow_.srcadd]
#-------------------------------------------------------------------------------
    def lookupflow(self,tiippkt_):
        ippkt_=tiippkt_[1]
        # se il pacchetto ippkt_ fa parte di un flusso nel db
        # ritorno il flusso
        if ippkt_.src in self and ippkt_.dst in self[ippkt_.src]:
            if ippkt_.data.sport in self[ippkt_.src][ippkt_.dst] and \
                   ippkt_.data.dport in self[ippkt_.src][ippkt_.dst][ippkt_.data.sport]:
                flow_=self[ippkt_.src][ippkt_.dst][ippkt_.data.sport][ippkt_.data.dport]
                flow_.setdir("fclient")
                flow_.setcurpkt(tiippkt_)
                return flow_
        elif ippkt_.dst in self and ippkt_.src in self[ippkt_.dst]:
            if ippkt_.data.dport in self[ippkt_.dst][ippkt_.src] and \
                   ippkt_.data.sport in self[ippkt_.dst][ippkt_.src][ippkt_.data.dport]:
                flow_=self[ippkt_.dst][ippkt_.src][ippkt_.data.dport][ippkt_.data.sport]
                flow_.setdir("fserver")
                flow_.setcurpkt(tiippkt_)
                return flow_
        else:
            return
#-------------------------------------------------------------------------------
    def countflows(self):            
        flows_=0
        # conteggia tutti i flussi nel database
        for srcadd_ in self:
            for dstadd_ in self[srcadd_]:
                for srcport_ in self[srcadd_][dstadd_]:
                    for dstport_ in self[srcadd_][dstadd_][srcport_]:
                        self[srcadd_][dstadd_][srcport_][dstport_].logmsg('presente')
                        flows_=flows_+1
        return flows_
#-------------------------------------------------------------------------------
    def xml_report(self):            
        report = '<?xml version="1.0" ?><report>\n'

        # conteggia tutti i flussi nel database
        for srcadd_ in self:
            for dstadd_ in self[srcadd_]:
                for srcport_ in self[srcadd_][dstadd_]:
                    for dstport_ in self[srcadd_][dstadd_][srcport_]:
                        #self[srcadd_][dstadd_][srcport_][dstport_].logmsg('presente')
                        pkts = self[srcadd_][dstadd_][srcport_][dstport_]._pkts
                        start_time = self[srcadd_][dstadd_][srcport_][dstport_].start_time
                        end_time = self[srcadd_][dstadd_][srcport_][dstport_].end_time
                        report += "<flow>\n  <src>%s</src>\n  <dst>%s</dst>\n  <sport>%s</sport>\n  <dport>%s</dport>\n  <start_time>%f</start_time>\n  <end_time>%f</end_time>\n  <packets>%s</packets>\n</flow>\n" % (dnet.ip_ntoa(srcadd_), dnet.ip_ntoa(dstadd_), srcport_, dstport_, start_time, end_time, pkts)
        report += "</report>\n"
        return report
class fcap:
    def __init__(self,name=None,snaplen=65535,promisc=True,immediate=False):
        self._flow2close=None
        self._errormsg=None
        self._verbose = 0
        # nuovo DB per il tracking dei flussi
        self.conntrack=TrackDB()

        # apre un catturatore di pacchetti
##        self.pc = pcap.pcap(name,snaplen,promisc,immediate)
        self.__pc_fl = open(name, 'rb')
        self.pc = dpkt.pcap.Reader(self.__pc_fl)
        self._filename = name
        self._all_read_packets = list()
#-------------------------------------------------------------------------------
    def isOnError(self):
        if self._errormsg:
            return True
#-------------------------------------------------------------------------------
    def errorStr(self):
        return self._errormsg
#-------------------------------------------------------------------------------
    def setVerbosity(self,verbosity_):
        self._verbose=verbosity_
#-------------------------------------------------------------------------------
    def __iter__(self):
        return self
#-------------------------------------------------------------------------------
#    def next(self, tipkt, pkt_idx):
    def run(self):
        pkt_idx = 0
        #while True:
        for tipkt in self.pc:
#                print tipkt[0]
#            try:
                # controlla se c'e' un flusso da rimuovere
                # si tratta di un flusso che al passaggio precedente
                # e' stato chiuso da FIN o RST
                #if self._flow2close:
                #    print "flow2close"
                #    self.conntrack.togliramo(self._flow2close)
                self._flow2close=None

                # reimplementa la macchina a stati del tcp
                # restituisce il flusso di cui e' arrivato un nuovo pacchetto
                # return a couple with (ts,pkt): it is a TImed PacKeT
#                tipkt=self.pc.next()
                pkt_idx += 1
#                print pkt_idx
                ti=tipkt[0]
                pkt=tipkt[1]
                self._all_read_packets.append((ti, pkt_idx, self._filename))
                
                if dpkt.ethernet.Ethernet(pkt).type != 2048:
#                    print "non 2048"
                    continue
                ippkt=dpkt.ethernet.Ethernet(pkt).data
                #if ippkt.p != 6:
#                    print "non 6"
                 #   continue
                tcp=ippkt.data
                length=ippkt.len
		        #DEBUG added the "skip" for pkts not well-formed
                try:
                    (dstadd,srcadd)=(ippkt.dst,ippkt.src)
                except:
                    print("malformato ip")
                continue
                try:
                    (dstport,srcport)=(tcp.dport,tcp.sport)
                except:
                    print("malformato tcp")
                    continue
                flags=tcp.flags
                SYN=flags & 2
                ACK=flags & 16
                FIN=flags & 1
                RST=flags & 4

                # now build up a new tiippkt: TImed IP PacKeT
                tiippkt=(ti,ippkt)
                # identifico il flusso: se non lo conosco "flow" e' vuoto
                flow=self.conntrack.lookupflow(tiippkt)

                # se SYN: nuovo flusso, timeout SYN vecchio. DEVO essere in stato 0
                # se nuovo vado in stato 0 e creo ramo
                # se gia' conosciuto elimino il flusso e ricreo
                if SYN and not ACK:
                    # se flusso gia' visto e direzione giusta riparto, altrimenti err
                    if flow and flow.isfclient():
                        if flow.getstatus()!=0:
                            if self._verbose>=2:
                                flow.logmsg("New SYN from client on a connected flow: reset flow")
                        else:
                            if self._verbose>=2:
                                flow.logmsg("New SYN again: reset flow")
                        self.conntrack.togliramo(flow)
                    elif flow:
                        self._errormsg=flow.flow2str()+"New SYN from server: wrong direction, fix it!"
                        raise StopIteration
                    #if not (ord(flow[0][0])==192 and ord(flow[0][1])==167 and (ord(flow[0][2]) in range(20,23))):
                    #	flow.logmsg("Flusso originato da fuori dell'universita")
                    #	continue
#                    print "crea ramo", flow
#                    flow=self.conntrack.crearamo(tiippkt,pkt_idx)
                    flow=self.conntrack.crearamo(tiippkt)
                    flow.start_time = ti
#                    print "l'ho creato", self.conntrack
                    if self._verbose>=2:
                        flow.logmsg("New SYN: set flow status to 0")
                    flow.setstatus(0)
#                    print "ho settato lo status"

                # se non conosco il flusso, itero
                elif not flow:
                    if self._verbose>=3:
                        Flow(tiippkt).logmsg("Unknown flow, skip packet")
                    continue

                # chiusura (per me) del 3-way-handshake
                # se e' in direzione fclient genera eccezione
                elif SYN and ACK:
#                    print "mi fermo SYN e ACK"
                    if flow.isfclient():
                        self._errormsg=flow.flow2str()+"SYN+ACK: wrong direction, fix it!"
                        raise StopIteration
                    if flow.getstatus()==0:
                        if self._verbose:
                            flow.logmsg('Connected: set flow status to 1')
                        flow.setstatus(1)
                        #flow._pkts.append(pkt_idx)
                    else:
                        #flow._pkts.append(pkt_idx)
                        if self._verbose>=2:
                            flow.logmsg("SYN+ACK on an already connected flow: don't care")

                # se sono ancora in stato 0 c'e' qualche cosa di strano
                # elimino il flusso e procedo
                elif flow.getstatus()==0:
                    if self._verbose:
                        flow.logmsg("Received a packet before 3whs-end: skip flow")
                    self.conntrack.togliramo(flow)
                    continue

                # aggiungo pacchetto alla sessione
                #flow._sess.add((ts,pkt))
                flow._pkts.append(pkt_idx)

                # c'e' un Reset (R)
                if RST:
                    #flow._pkts.append(pkt_idx)
                    if self._verbose:
                        flow.logmsg("RST End")
                    self._flow2close=flow
                    flow.end_time = ti
                    flow._finished=1

                # se FIN e stato==1: wait FIN da altro end-point
                elif FIN and flow.getstatus()==1:
                    #flow._pkts.append(pkt_idx)
                    if self._verbose>=2:
                        flow.logmsg("First FIN: set flow status to 2")
                    flow.setstatus(2)
                    flow.setfin(srcadd)

                # FIN successivo al primo FIN (quindi nell'altra direzione)
                # Adesso dobbiamo attendere l'ultimo ACK nell'altra direzione
                elif FIN and flow.getstatus()==2 and flow.getfin()==dstadd:
                    #flow._pkts.append(pkt_idx)
                    if self._verbose>=2:
                        flow.logmsg("Second and opposite FIN: set flow status to 3")
                    flow.setstatus(3)
                    flow.setfin(srcadd)

                # ACK successivo al secondo FIN, se in stato 3 chiudo connessione
                elif ACK and flow.getstatus()==3 and flow.getfin()==dstadd:
#                    print "ho chiuso"
                    #flow._pkts.append(pkt_idx)
                    if self._verbose:
                        flow.logmsg('FIN End')
                    self._flow2close=flow
                    flow.end_time = ti
                    flow._finished=1

                flow.setcurl2pkt(tipkt)
                #return flow
        
#            except StopIteration:
#                raise
        self.__pc_fl.close()
#-------------------------------------------------------------------------------
    def countflows(self):
        return self.conntrack.countflows()
    
    def xml_report(self):
        return self.conntrack.xml_report()
    
