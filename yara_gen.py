# -*- coding: utf-8 -*-
from __future__ import print_function, absolute_import

import re
import sys
import string
import argparse
import datetime

from jinja2 import Template, Environment

__author__ = "Jaume Martin"
__version__ = "0.1.0"
__date__ = datetime.datetime.utcnow()
__repo__ = "https://git.todoparami.net/Xumeiquer/PEiD_to_Yara"

RULES = """/*
YARA rules generated with {{ file }}
BY: {{ author }}
GITHUB: {{ repo }}
GENERATED ON: {{ date_time }}

*/
import "pe"

{% for rule_name, rule_data in rules.iteritems() %}
{% set outer_loop = loop %}
{% for variant, data in rule_data.iteritems() %}
rule {#PEiD_{{ outer_loop.index }}_#}{{ rule_name }}: PEiD
{
    meta:
        author = "{{ author }}"
        description = "{{ rule_name }} -> {{ variant }}"
        ref = "https://raw.githubusercontent.com/guelfoweb/peframe/5beta/peframe/signatures/userdb.txt"
    strings:
        {% set letter = "" %}
        {% for d in data %}
        {% set letter = next_var(letter) %}
        ${{ letter }} = { {{ d.signature }} }
        {% endfor %}
    condition:
    {% if data|length > 1 %}
        for any of ($*) : ( $ at pe.entry_point )
    {% else %}
        $a at pe.entry_point
    {% endif %}

}\n
{% endfor %}
{% endfor %}
"""

parser = argparse.ArgumentParser(
    description=u'Parse PEiD packer signatures and generates yara rules')
parser.add_argument(u'-f', u'--file', action=u'store', nargs=u'+',
                    help=u'PEiD databse files')
parser.add_argument(u'-o', u'--output', action=u'store', required=True, nargs=1,
                    help=u'File with a bunch of yara rules')


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

# guarantee unicode string
_u = lambda t: t.decode('UTF-8', 'replace') if isinstance(t, str) else t


def peid_parser(file_name, obj):
    rules = []
    line_idx = 0
    with open(file_name, 'Ur') as r_file:
        for line in r_file.readlines():
            line = line.rstrip('\n')
            if line.startswith(";") or len(line) == 0:  # This is a rule
                continue

            if line_idx == 0:
                rule_name = None
                variant = None
                signature = None
                ep_only = None

            if line.startswith("["):  # Rule name
                line = re.sub(
                    "(\[|\]|[$#*!/()',`´:;?¿<>&%¡^~\"@|])*", "", line)
                line = re.sub("(-)[^>]", "_", line)
                line = re.sub("--", "-", line)
                line = re.sub("\.", "_", line)
                line = re.sub("\+", "plus", line)
                line = re.sub(r"[^\x00-\x7F]+", "", line)
                line = line.strip()
                if line[0].isdigit():
                    line = "_" + line
                if not "->" in line:
                    rule_name = line
                    variant = line
                else:
                    if len(line.split("->")) > 2:
                        tmp = line.split("->")
                        rule_name = tmp[0]
                        variant = ""
                        for i in range(1, len(tmp)):
                            variant += tmp[i]
                    else:
                        rule_name, variant = line.split("->")
            if line.startswith("signature"):
                signature = line.split("signature = ")[1]
                last_word = signature[len(signature) - 2:]
                if " " in last_word:
                    signature += "?"
            if line.startswith("ep_only"):
                ep_only = line.split("ep_only = ")[1]

            if rule_name:
                rule_name = rule_name.strip()
                rule_name = re.sub("[ ]+", "_", rule_name)
            if variant:
                variant = variant.strip()
                variant = re.sub("[ ]+", "_", variant)

            if line_idx == 2:
                if obj.has_key(_u(rule_name)):
                    if obj[_u(rule_name)].has_key(_u(variant)):
                        if not any(vs['signature'] == signature for vs in obj[_u(rule_name)][_u(variant)]) or \
                                not any(ep['ep_only'] == ep_only for ep in obj[_u(rule_name)][_u(variant)]):
                            obj[_u(rule_name)][_u(variant)].append(
                                {"signature": _u(signature), "ep_only": ep_only})
                    else:
                        obj[_u(rule_name)][_u(variant)] = [
                            {"signature": _u(signature), "ep_only": ep_only}]
                else:
                    obj[_u(rule_name)] = {
                        _u(variant): [{"signature": _u(signature), "ep_only": ep_only}]}

            if line_idx == 2:
                line_idx = 0
            else:
                line_idx += 1
    return obj


if __name__ == '__main__':
    args = parser.parse_args()
    rules_obj = {}
    for file in args.file:
        rules_obj = peid_parser(file, rules_obj)

    tpl = Environment(trim_blocks=True,
                      lstrip_blocks=True).from_string(RULES)
    tpl.globals['next_var'] = increment_str
    yara_rules = tpl.render(author=__author__,
                            date_time=__date__,
                            file=__file__,
                            version=__version__,
                            repo=__repo__,
                            rules=rules_obj)
    with open(args.output[0], "w") as yara_rules_f:
        yara_rules_f.write(_u8(yara_rules))
