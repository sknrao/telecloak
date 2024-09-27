FROM ubuntu:22.04

RUN apt update
RUN apt install -y build-essential autoconf python3 python3-pip python3 git libxerces-c-dev nettle-dev libboost-all-dev

WORKDIR /anon
RUN apt install -y pkg-config automake
RUN git clone https://github.com/KIT-Telematics/pktanon.git
RUN apt install -y libpcap-dev
RUN cd pktanon && ./bootstrap && ./configure && make
RUN cd pktanon && make install

ADD ./l7anon /anon/l7anon
RUN pip install pyinstaller
RUN cd /anon/l7anon && pyinstaller --onefile tcpanon.py
RUN cp /anon/l7anon/dist/tcpanon /bin/

RUN git clone https://github.com/libcheck/check.git
RUN git clone https://github.com/ofalk/libdnet.git
RUN pip install Cython dpkt
RUN apt install -y texinfo libtool

RUN cd check && autoreconf --install && ./configure && make && make install
RUN cd libdnet && ./configure && make && make install
RUN cd libdnet/python && python3 setup.py build && python3 setup.py install

ADD ./scrub-tcpdump-optimized /anon/scrub-tcpdump
RUN cd scrub-tcpdump && make
RUN cd scrub-tcpdump && cp scrub-tcpdump /bin/

RUN pip install minio
RUN pip install requests

ADD app.py /anon/

RUN apt install -y vim

CMD ["python3", "app.py"]
