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
This module is intendend to perform pop3-data anonymization.

In addition the program can be launched as a command line utility.
"""

import os, sys
from string_plus import *


def process_pop3(src):
    """
    process_pop3(src)
    
    This function handles pop3 streams. Basically it fakes sensible data
    in commands and replies and hides contents where there are no human
    readable messages.
    
    src : source data. Either an already opened file or a string.
    
    Returns the processed stream within a string.
    """
    
    if type(src) is file:
        source_stream = src.readlines()
    elif isinstance (src, str):
        source_stream = src.splitlines(True)
    else:
        raise TypeError("The input parameter is neither a file object nor a string")
    
    out = str()
    delimiters = (('<','>'), ('[',']'), ('(',')'))
    pattern = r'\b\S+\.[a-zA-Z]{2,4}\b'
    
    # The idea is to let data trough until TRANSACTION State
    # and should work fine with the first Multi-Line end;
    # anyway recipients and FQDNs are always anonymized because of
    # malformed packets/sessions
    CLEAR = True
    
    for line in source_stream:
        if string.startswith(line, ('.' + CRLF,)):
            anonymized = line
            CLEAR = False
        
        # commands are case-insensitive
        elif string.startswith(line.upper(), ('STAT' + CRLF, 'NOOP' + CRLF, 'RSET' + CRLF, 'QUIT' + CRLF,\
            'UIDL' + CRLF, 'LIST' + CRLF, '+OK' + CRLF, '-ERR' + CRLF, CRLF)):
            anonymized = line 
        # LIST e UIDL may come with optional messages
        elif string.startswith(line.upper(), ('LIST ', 'UIDL ', 'RETR ', 'DELE ', 'USER ', 'PASS ', 'AUTH ',\
            'NOOP ', 'TOP ', 'APOP ')):
            splitted = line.split(" ", 1)
            anonymized = " ".join([splitted[0], string.anonymize_line(splitted[1])])
        # keep +OK and -ERR human readable
        # status indicator (+OK and -ERR) are not case insensitive
        elif string.startswith(line, ('+OK', '-ERR')):
            anonymized = re.sub(pattern, anonymize, line)
        else:
            if CLEAR:
                anonymized = re.sub(pattern, anonymize, line)
            else:
                anonymized = string.anonymize_line(line)
        out += anonymized
    
    return out


if __name__ == "__main__":
    
    in_files = sys.argv[1:]
    
    if not in_files:
        usage = "Usage: %s file_1 [... file_n]\n\nOutput: file_1.anon [... file_n.anon]\n"\
            % sys.argv[0].lstrip("./")
        print(usage)
        sys.exit(2)
    
    for input in in_files:
        try:
            src = file(input)
        except:
            e = 'Input file "' + input + '" not present or bad file'
            raise IOError(e)
        
        try:
            dst = file(os.path.basename(input) + ".anon", 'w')
            dst.write(process_pop3(src))
        except IOError:
            raise IOError("Output error: maybe this directory is not writable?")
        except:
            raise
##        finally: python 2.5!
        src.close()
        dst.close()
