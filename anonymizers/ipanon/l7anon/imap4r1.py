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
This module is intendend to perform imap4rev1-data anonymization.

In addition the program can be launched as a command line utility.
"""

import os, sys
from string_plus import *


def process_imap4(src):
    """
    process_imap4(src)
    
    This function handles imap4 streams. Basically it fakes sensible data
    in FETCH commands and no more than this.
    
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

    # pyparsing grammar stuff
    tag = Word(alphanums + '*')
    command = oneOf("SELECT LIST LSUB STATUS select list lsub status")
    pattern = tag + command + restOfLine
    
    domain_pattern = r'\b\S+\.[a-zA-Z]{2,4}\b'
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    path_pattern = r'/.*\b'
    
    # server responses start with a tag, '*' or '+'
    # the first character issued from the server side it's '*'
    client = True
    try:
        if source_stream[0][0] == '*':
            client = False
    except:
        pass
        
    # TODO:  APPEND come FETCH?
    fetch = False

    for line in source_stream:
        if not fetch:
            # looking for untagged response
            if line.startswith('* ') and 'FETCH (' in line.upper():
                # an untagged fetch 
                if not line.endswith(')' + CRLF):
                    fetch = True
                anonymized = line
            # all the rest
            elif 'SELECT' in line.upper() or\
                 'LIST' in line.upper() or\
                 'LSUB' in line.upper() or\
                 'STATUS' in line.upper():
                try:
                    parse_result = pattern.parseString(line).asList()
                    parse_result[-1] = string.anonymize(parse_result[-1].strip(CRLF), shorten=1) + CRLF
                    anonymized = " ".join(list(parse_result))
                except ParseException:
                    anonymized = line                    
            else:
                if client:
                    # user and password (and 'DONE') are the only not tagged
                    if len(line.split()) == 1 and line != 'DONE' + CRLF:
                        anonymized = string.anonymize_line(line)
                    else:
                        anonymized = line
                else:
                    # kinda testing due to lack of imap sessions
                    # that's why we run a pattern at a time
                    anonymized = re.sub(ip_pattern, anonymize, line)
                    anonymized = re.sub(domain_pattern, anonymize, anonymized)
                    anonymized = re.sub(path_pattern, anonymize, anonymized)
        else:
            if line == ')' + CRLF:
                anonymized = line
                fetch = False
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
            dst.write(process_imap4(src))
        except IOError:
            raise IOError("Output error: maybe this directory is not writable?")
        except:
            raise
##        finally: python 2.5!
        src.close()
        dst.close()
