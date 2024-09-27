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
This module is intendend to perform http-data anonymization.

In addition the program can be launched as a command line utility.
"""

import os, sys
from string_plus import *
import configparser


class EmptyConfig(configparser.Error):
    """Raised when there's no file to read."""
    def __init__(self, config_file):
        configparser.Error.__init__(self, "There's no file called %s in this path" % config_file)
        self.config_file = config_file
      
def process_http(src, config_file='tcpanon.config', verbose=False):
    """
    process_http(src)
    
    This function handles http streams. Basically it fakes sensible info
    in commands and replies and hides contents.
    
    src : source data. Either an already opened file or a string.
    
    Returns the processed stream within a string.
    """
    
    if type(src) is file:
        source_stream = src.readlines()
    elif isinstance (src, str):
        source_stream = src.splitlines(True)
    else:
        raise TypeError("The input parameter is neither a file object nor a string")
    
    # config stuff
    keep_tag = list()
    keep_all = list()
    
    try:
        cfg_parser = configparser.SafeConfigParser()
        # case sensitive for the field name
        cfg_parser.optionxform = str
        config = cfg_parser.read(config_file)
        if not bool(config):
            raise EmptyConfig(config_file)
        else:
            for elem in cfg_parser.items('http'):
                if elem[1].upper() == 'TAG':
                    keep_tag.append(elem[0])
                elif elem[1].upper() == 'ALL':
                    keep_all.append(elem[0])
                elif elem[1].upper() == 'NONE':
                    pass
                else:
                    print("\nIncorrect setting '%s: %s': Ignoring...\n" % elem)
    except EmptyConfig:
        # show a warning and then go ahead with default configuration
        print("\nSomething went wrong while reading configuration file '%s':\n" % config_file\
            + 'It seems there\'s no file like that in the current path.\n'\
            + 'We go ahead with the default configuration.\n')
        
        keep_tag = ('Host:', 'User-Agent:', 'Cookie:', 'Referer:', 'Content-Type:')
        keep_all = ('Accept-Charset:', 'Accept-Encoding:' , 'Accept-Language:',\
            'Content-Length:', 'Keep-Alive:', 'HTTP/1')
    except:
        print("Something went wrong while reading configuration file '%s'.\nExiting...\n" % config_file)
        raise
    
    out = str()

    for line in source_stream:
        # METHODs end with <CRLF>
        if string.startswith(line, ('GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'TRACE', 'CONNECT')):
            anonymized = string.anon_bd(line, [(' ', ' ')])
        # keep HEADER fields
        elif string.startswith(line.upper(), keep_tag):
            try:
                splitted = line.split(" ", 1)
                anonymized = " ".join([splitted[0], string.anonymize_line(splitted[1])])
            except:
                if verbose:
                    print("malformed HTTP field")
                anonymized = line
        # keep all
        elif string.startswith(line.upper(), keep_all):
           anonymized = line
        # to keep it far from header fields
        elif line.startswith(CRLF) or line.startswith('\n'):
           anonymized = line
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
            dst.write(process_http(src))
        except IOError:
            raise IOError("Output error: maybe this directory is not writable?")
        except:
            raise
##        finally: python 2.5!
        src.close()
        dst.close()
