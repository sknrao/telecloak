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
This module is intendend to perform ftp-data anonymization
of both command and data channels.

In addition the program can be launched as a command line utility.
"""

# FTP commands: RFC959 pag. 47 - case insensitive
# USER <SP> <username> <CRLF>
# PASS <SP> <password> <CRLF>
# ACCT <SP> <account-information> <CRLF>
# CWD <SP> <pathname> <CRLF>
# CDUP <CRLF>
# SMNT <SP> <pathname> <CRLF>
# QUIT <CRLF>
# REIN <CRLF>
# PORT <SP> <host-port> <CRLF>
# PASV <CRLF>
# TYPE <SP> <type-code> <CRLF>
# STRU <SP> <structure-code> <CRLF>
# MODE <SP> <mode-code> <CRLF>
# RETR <SP> <pathname> <CRLF>
# STOR <SP> <pathname> <CRLF>
# STOU <CRLF>
# APPE <SP> <pathname> <CRLF>
# ALLO <SP> <decimal-integer>
#      [<SP> R <SP> <decimal-integer>] <CRLF>
# REST <SP> <marker> <CRLF>
# RNFR <SP> <pathname> <CRLF>
# RNTO <SP> <pathname> <CRLF>
# ABOR <CRLF>
# DELE <SP> <pathname> <CRLF>
# RMD <SP> <pathname> <CRLF>
# MKD <SP> <pathname> <CRLF>
# PWD <CRLF>
# LIST [<SP> <pathname>] <CRLF>
# NLST [<SP> <pathname>] <CRLF>
# SITE <SP> <string> <CRLF>
# SYST <CRLF>
# STAT [<SP> <pathname>] <CRLF>
# HELP [<SP> <string>] <CRLF>
# NOOP <CRLF>


# FTP replies (N is a digit)
# single line: NNN <SP> <string> <CRLF>
# multi line : NNN <-> <string> <CRLF>
#              <line2>
#              <line3>
#              <SP>nnn <rest of line>
#              NNN <SP> [<string>] <CRLF>  <-- RFC
#              NNN [<SP> <string>] <CRLF>  <-- possibly?

import os, sys
from pyparsing import Word, nums, restOfLine, Optional
from string_plus import *


def process_ftp(src):
    """
    process_http(src)
    
    This function handles ftp control streams. Basically it fakes sensible info
    in commands and replies while looking for data connections.
    
    src : source data. Either an already opened file or a string.
    
    Returns the processed stream within a string and a list of (host, port).
    """
    
    if type(src) is file:
        source_stream = src.readlines()
    elif isinstance (src, str):
        source_stream = src.splitlines(True)
    else:
        raise TypeError("The input parameter is neither a file object nor a string")
    
    out = str()
    
    ftp_reply_pattern = Word(nums, exact=3) + Optional("-") + restOfLine
    
    ftp_data_connection = list()
    MAX_COMMAND_LENGTH = 4 + 2
    MULTILINE = False
    MULTILINE_CODE = str()
        
    for line in source_stream:
        
        try:
            if MULTILINE:
                pass
            else:
                ftp_reply_pattern.parseString(line)
            
        # it's a command or data
        except:
            # keep command
            if string.startswith(line.upper(), ('CDUP' , 'QUIT', 'REIN', 'PASV', 'STOU', 'ALLO' + CRLF,\
                'ABOR', 'PWD', 'SYST', 'NOOP')):
                anonymized = line
            else:
                splitted = line.split(" ", 1)
                if string.startswith(line.upper(), 'PORT '):
                    ftp_data_connection.append(string.ftp_data_port(splitted[1]))
                # not expected stuff.. (also lowercase)
                if len(splitted[0]) <= MAX_COMMAND_LENGTH:
                    # we assume it's a command
                    if len(splitted) > 1:
                        anonymized = " ".join([splitted[0], string.anonymize_line(splitted[1])])
                    else:
                        anonymized = line
                else:
                    # it's data
                    anonymized = string.anonymize_line(line)
        # it's a reply
        else:
            # reset multiline replies
            if line[:3] == MULTILINE_CODE:
                MULTILINE = False
                MULTILINE_CODE = ''
            
            # set multiline replies
            if line[3] == '-':
                MULTILINE = True
                MULTILINE_CODE = line[:3]
            
            if line.startswith('220'):
                anonymized = string.anon_bd(line, [('<','>'), ('[',']'), ('(',')')])
            elif line.startswith('227'):
                data_string = line[1 + line.find('('): line.find(')')]
                ftp_data_connection.append(string.ftp_data_port(data_string))
                anonymized = string.anon_bd(line, [('(', ')')])
            elif string.startswith(line, ('150', '214 ', '230', '250', '257', '331', '550')):
                splitted = line.split(" ", 1)
                try:
                    anonymized = " ".join([splitted[0], string.anonymize_line(splitted[1])])
                except:
                    # for example "230-"
                    anonymized = line
            # keep as is
            else:
                anonymized = line
        
        out += anonymized
    
    if __name__ == "__main__":
        if ftp_data_connection:
            print("ftp data connections found:\n")
            for conn in ftp_data_connection:
                print(conn)
        return out
    else:
        return out, ftp_data_connection


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
            dst.write(process_ftp(src))
        except IOError:
            raise IOError("Output error: maybe this directory is not writable?")
        except:
            raise
##        finally: python 2.5!
        src.close()
        dst.close()
