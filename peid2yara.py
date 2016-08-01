#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, absolute_import

import re
import sys
import string
import argparse
import datetime

try:
    import colorama as color
except:
    COLOR = False
else:
    color.init()
    COLOR = True

from jinja2 import Template, Environment

__author__ = "Jaume Martin"
__version__ = "0.2.0"
__date__ = datetime.datetime.utcnow()
__repo__ = "https://git.todoparami.net/Xumeiquer/PEiD_to_Yara"

RULES = """/*
YARA rules generated with {{ file }}
BY: {{ author }}
GITHUB: {{ repo }}
GENERATED ON: {{ date_time }}

*/

import "pe"

{% for signame, rule_data in rules.iteritems() %}
{% if isdigit(signame) %}
rule PEiD_{{ loop.index }}_{{ signame }}: PEiD
{% else %}
rule {{ signame }}: PEiD
{% endif %}
{
    meta:
        author = "{{ author }}"
        description = "{{ signame }}"
    strings:
        {% set letter = "" %}
        {% for d in rule_data %}
        {% set letter = next_var(letter) %}
        ${{ letter }} = { {{ d.signature }} }
        {% endfor %}
    condition:
    {% if rule_data|length > 1 %}
        for any of ($*) : ( $ at pe.entry_point )
    {% else %}
        $a at pe.entry_point
    {% endif %}

}\n
{% endfor %}
"""

parser = argparse.ArgumentParser(
    description=u'Parse PEiD packer signatures and generates yara rules')
parser.add_argument(u'-f', u'--file', action=u'store', nargs=u'+',
                    help=u'PEiD databse files')
parser.add_argument(u'-o', u'--output', action=u'store', required=True, nargs=1,
                    help=u'File with a bunch of yara rules')
parser.add_argument(u'-A', u'--autofix', action=u'store_true', required=False, default=False,
                    help=u'Tries to autofix a PEiD signature by adding ? in front of or behind. WARNING: This option could mess the rule, use at your own risk.')
parser.add_argument(u'-v', u'--verbose', action=u'store_true', required=False, default=False,
                    help=u'Vervose output')


SIGNAME = re.compile("^\[(?P<signame>.*)\]$")
SIGNATURE = re.compile(
    "^signature[ ]?=[ ]?(?P<signature>.+)$", re.IGNORECASE)
EP_ONLY = re.compile("^ep_only ?= ?(?P<ep_only>true|false)$", re.IGNORECASE)
ACCEPTED_VALUES = re.compile("^([0-9A-F?]{2} ?)+$", re.IGNORECASE)

ERRORS = False


def increment_str(s):
    def increment_char(c):
        return chr(ord(c) + 1) if c != 'z' else 'a'
    if s == "":
        return "a"
    lpart = s.rstrip('z')
    num_replacements = len(s) - len(lpart)
    new_s = lpart[:-1] + increment_char(lpart[-1]) if lpart else 'a'
    new_s += 'a' * num_replacements
    return new_s


def isdigit(w):
    return w[0].isdigit()

# guarantee unicode string
_u = lambda t: t.decode('UTF-8', 'replace') if isinstance(t, str) else t
# guarantee byte string in UTF8 encoding
_u8 = lambda t: t.encode('UTF-8', 'replace') if isinstance(t, unicode) else t


def peid_parser(file_name, obj, autofix=False, verbose=False):
    global SIGNAME, SIGNATURE, EP_ONLY, ACCEPTED_VALUES, ERRORS, NON_ACCEPTED_VALUES
    rules = []
    line_idx = 0
    with open(file_name, 'Ur') as r_file:
        count = 0
        for line in r_file.readlines():
            count += 1
            line = line.rstrip('\n')
            if line.startswith(";") or len(line) == 0:
                continue

            m = SIGNAME.match(line)
            if m:
                signame = re.sub(
                    "[\[\]$#*!/()',.`´:;?¿<>&%¡^~\"@|=]*", "", m.group("signame"))
                signame = re.sub(r"[^\x00-\x7F]+", "", signame)
                signame = re.sub("-|\.| ", "_", signame)
                signame = re.sub("\+", "p", signame)
                signame = re.sub("_+", "_", signame)
                signame = signame[0:99]
                skip = True
                continue

            m = SIGNATURE.match(line)
            if m:
                signature = m.group("signature")
                m = ACCEPTED_VALUES.match(signature)
                if not m:
                    ERRORS = True
                    if verbose:
                        if color:
                            print(color.Fore.RED + "[!] " + color.Fore.RESET + "Signature [{}] malformed in file {} at line {}, skipping...".format(
                                signame, file_name, count))
                        else:
                            print("[!] Signature [{}] malformed in file {} at line {}, skipping...".format(
                                signame, file_name, count))
                    if autofix:
                        if verbose:
                            if color:
                                print(
                                    color.Fore.CYAN + "[+] " + color.Fore.RESET + "Trying autofix...")
                            else:
                                print("[+] Trying autofix...")
                        first_word = signature[:-len(signature) + 2]
                        last_word = signature[len(signature) - 2:]
                        if " " in first_word:
                            signature = "?" + signature
                        if " " in last_word:
                            signature = signature + "?"
                        m = ACCEPTED_VALUES.match(signature)
                        if not m:  # Still valid
                            if verbose:
                                if color:
                                    print(
                                        color.Fore.RED + "[-] Unable to autofix..." + color.Fore.RESET)
                                else:
                                    print("[-] Unable to autofix...")
                            skip = True
                            continue
                    else:
                        continue
                skip = False

            m = EP_ONLY.match(line)
            if m and not skip:
                ep_only = m.group("ep_only")

                if obj.has_key(_u(signame)):
                    if not any(vs['signature'] == signature for vs in obj[_u(signame)]) and \
                            not any(ep['ep_only'] == ep_only for ep in obj[_u(signame)]):
                        obj[_u(signame)].append(
                            {"signature": _u(signature), "ep_only": ep_only})
                    else:
                        if verbose:
                            if color:
                                print("\t[-] " + color.Fore.CYAN + "Duplicate siganture {}, insertion avoided...".format(
                                    _u(signame)) + color.Fore.RESET)
                            else:
                                print("\t[-] Duplicate siganture {}, insertion avoided...".format(
                                    _u(signame)))
                else:
                    obj[_u(signame)] = [
                        {"signature": _u(signature), "ep_only": ep_only}]

    return obj


if __name__ == '__main__':
    args = parser.parse_args()
    rules_obj = {}
    for file in args.file:
        rules_obj = peid_parser(file, rules_obj, args.autofix, args.verbose)

    if ERRORS:
        if color:
            print("\n" + color.Fore.RED +
                  "[*] WARNING: Some rules fails during translation. " + color.Fore.RESET + " Re-run with -v option for more info.")
        else:
            print("\n[*] WARNING: Some rules fails during translation.")

    tpl = Environment(trim_blocks=True,
                      lstrip_blocks=True).from_string(RULES)
    tpl.globals['next_var'] = increment_str
    tpl.globals['isdigit'] = isdigit
    yara_rules = tpl.render(author=__author__,
                            date_time=__date__,
                            file=__file__,
                            version=__version__,
                            repo=__repo__,
                            rules=rules_obj)
    with open(args.output[0], "w") as yara_rules_f:
        yara_rules_f.write(_u8(yara_rules))
