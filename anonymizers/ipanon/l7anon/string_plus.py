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
#
# Further revisions by Luca Salgarelli <luca.salgarelli@ing.unibs.it> and
# Maurizio Dusi
#


"""
Enhancements to the standard string library to suit
TCP anonymization needs.
"""

import string
from pyparsing import *

CRLF = '\r\n'

def ftp_data_port(astring):
    """
    ftp_data_port(astring)
    
    This function returns (host, port) from a string 
    "h1, h2, h3, h4, p1, p2"
    where h1 is the high order 8 bits of the internet host address
    and p1 is the high order 8 bits of the port.
    """
    
    # if the format is not correct --> std errors will be raised
    elem = astring.split(',')
    host = '.'.join(elem[:4])
    port = (int(elem[4])<<8) + int(elem[5])
    return host, port


def anonymize(astring, with_char='x', shorten=0):
    """
    anonymize(astring[, with_char[,shorten]])
    
    Examples:
        anonymize('hello')
        'xxxxx'
        anonymize('hello', '0', 2)
        '000'
    """
    # for 'internal' use with pop3
    if type(astring) is not str:
        return with_char * len(str(astring.group()))
        
    return str(with_char) * (len(astring) -  shorten)


def anonymize_line(aline, with_char='x', end_of_line=''):
    """
    anonymize(aline[, with_char[,end_of_line]])
    
    Examples:
        anonymize_line('hello\r\n')
        'xxxxx\r\n'
        anonymize_line('hello\r\n', '0', end_of_line='\r')
        '00000\r'
    """
    
    if not end_of_line:
        if aline[-2:] == CRLF:
            end_of_line = CRLF
        elif aline[-1] in CRLF:
            end_of_line = aline[-1]
    
    return anonymize(aline.rstrip(CRLF), with_char) + end_of_line


def anon_bd(astring, delimiters, with_char='x'):
    """
    anon_bd(astring, delimiters[, with_char])
    
    ANONymize Between Delimiters
    
    astring     : string to analyze
    delimiters  : list (or tuple) of pairs of delimiters
    [with_char] : character to rewrite with
    
    Example:
        anon_bd("MAIL-TO Gianni (l'ottimista) <example@123.com>", [('<','>'),('(',')')], 'u')
        'MAIL-TO Gianni (uuuuuuuuuuu) <uuuuuuuuuuuuuuu>'
    """
    
    anonymized = astring
    
    if not type(delimiters) is tuple and not type(delimiters) is list:
        e = """
        delimiters MUST be a list (or tuple) of tuples
        
        Note:
            t1 = ("x") is NOT a tuple
            t2 = ("x",) is a tuple
        """
        raise TypeError(e)
        
        
    for couple in delimiters:
        dlim1, dlim2 = couple
        wdlim1 = Word(dlim1).leaveWhitespace()
        wdlim2 = Word(dlim2).leaveWhitespace()
        pattern = Optional(CharsNotIn(dlim1)) + wdlim1 + CharsNotIn(dlim2).setParseAction(\
                        lambda s,l,t : anonymize(str(t), with_char, 4))+ wdlim2 + Optional(restOfLine)
        try:
            anonymized = "".join(list(pattern.parseString(anonymized)))
            #parseString strips '\n'
            if astring[-1] == '\n':
                anonymized += '\n'
        except ParseException:
            # no pattern with delimiters found, nothing to do
            pass
        
    return anonymized


def startswith(astring, prefix):
    """
    startswith(astring, prefix)
    
    astring     : string to analyze
    prefix      : prefix tuple/list
    
    NOTE:
        This function's been written to ensure a lighter matching definition layout
        within the tasks, exactly like Python 2.5 allows, but still operating with
        older versions of Python.
    """
    #    Questa funzione e' stata scritta per mantenere leggera la scrittura del matching
    #    nei vari task, esattamente come in Python 2.5, conservando la portabilita' rispetto
    #    alle versioni precedenti di Python.
    
    
    if (not type(prefix) is tuple) and (not type(prefix) is list):
        if isinstance(prefix, str):
            prefix = (prefix,)
        else:
            raise TypeError("prefix should be either a tuple or a list")
    
    for elem in prefix:
        if astring.startswith(elem.upper()):
            return True
    else:
        return False


string.crlf = CRLF
string.anonymize = anonymize
string.anonymize_line = anonymize_line
string.anon_bd = anon_bd
string.startswith = startswith
string.ftp_data_port = ftp_data_port
