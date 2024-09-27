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
This module is intendend to perform smtp-data anonymization:
look at process_smtp first.

In addition the program can be launched as a command line utility.
"""

import os, sys
from pyparsing import Word, nums, restOfLine, Optional 
from string_plus import *


def anon_reply_cmd(line, reply_pattern):
    """
    anon_reply_cmd(line, reply_pattern)
    NOTE: server_name and server_anon are also needed in a reachable scope.
    
    This function is called to anonymize replies and commands.
    
    Smtp replies consist of a 3 digit number eventually followed
    by human readable text. A dash after the 3 digit number denotes
    a multiline reply.
    
    Smtp commands list is well known: EHLO, HELO, MAIL, RCPT, DATA,
    RSET, VRFY, EXPN, HELP, NOOP and QUIT.
    
    The purpose is to hide data like <recipient> and [address].
    
    """
    
    # A closer look, still incomplete, to the command syntax from RFC 2821:
    #
    # EHLO<space>domain<CRLF>
    # HELO<space>domain<CRLF>
    # MAIL<space>FROM:[parameters]<CRLF>
    # RCPT<space>TO:[parameters]<CRLF>
    # DATA<CRLF>
    # RSET<CRLF>
    # VRFY<space>text<CRLF>
    # EXPN<space>text<CRLF>
    # HELP[<space>text]<CRLF>
    # NOOP[<space>text]<CRLF>
    # QUIT<CRLF>
    
    # <recipient> [address]
    delimiters = (('<','>'), ('[',']')) 
    # is it a reply?
    try:
        reply_pattern.parseString(line)
    # it's a command
    except ParseException:
        if string.startswith(line, ('MAIL','RCPT')):
            return string.anon_bd(line, delimiters)
        if string.startswith(line, ('QUIT','RSET','HELP' + CRLF,'NOOP' + CRLF)):
            return line
        if string.startswith(line, ('EHLO', 'HELO', 'VRFY', 'EXPN', 'HELP ', 'NOOP ')):
            # TODO: anonimizzare di meno?
            # VRFY mette recipients, usernames
            splitted = line.split(" ", 1)
            return " ".join([splitted[0], string.anonymize_line(splitted[1])])
        
        return "Do I miss something?!" + CRLF
    # it's a reply
    else:
        # replace server_name
        anonymized = line.replace(server_name, server_anon)
        # replace recipient, address
        if not string.startswith(line, ('354 ')):
            anonymized = string.anon_bd(anonymized, delimiters)
        return anonymized

def process_smtp(src):
    """
    process_smtp(src)
    
    This function handles smtp streams. Basically it hides contents
    issued between "DATA" and "." commands and then relies on anon_reply_cmd.
    
    src : source data. Either an already opened file or a string.
    
    Returns the processed stream within a string.
    """
    
    # prevent_local_scope
    global server_name, server_anon
    content = False
    smtp_reply_pattern = Word(nums, exact=3) + Optional("-") + restOfLine
    
    if type(src) is file:
        source_stream = src.readlines()
    elif isinstance (src, str):
        source_stream = src.splitlines(True)
    else:
        raise TypeError("The input parameter is neither a file object nor a string")
    
    out = str()
    
    for line in source_stream:
        # output <CRLF> immediately
        if line == CRLF:
##            dst.write(line)
            out += line
        elif content:
            # reset content flag on DATA end
            if line == "." + CRLF:
##                dst.write(line)
                out += line
                content = False
            else:
##                dst.write(string.anonymize(line) + CRLF)
                out += string.anonymize_line(line)
        else:
            # if DATA then set content flag
            if line == "DATA" + CRLF:
##                dst.write(line)
                out += line
                content = True
            else:
                # strip server_name from READY message
                if line.startswith("220"):
                    # same for multiline and single line
                    READY = line.replace("220 ", "220-")
                    server_name = READY.split()[0].lstrip("220-")
                    server_anon = string.anonymize(server_name, "s")
##                dst.write(anon_reply_cmd(line, smtp_reply_pattern))
                out += anon_reply_cmd(line, smtp_reply_pattern)
    
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
            dst.write(process_smtp(src))
        except IOError:
            raise IOError("Output error: maybe this directory is not writable?")
        except:
            raise
##        finally: python 2.5!
        src.close()
        dst.close()
