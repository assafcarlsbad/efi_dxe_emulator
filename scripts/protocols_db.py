import argparse
import click
import glob
import json
import os
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--directory', help='extracted modules directory from UEFIExtract')
parser.add_argument('-n', '--nvram', help='extracted NVRAM file from UEFITool')
parser.add_argument('-e', '--emulator', help='path to the UEFI DXE emulator')
parser.add_argument('-o', '--output', default='protocols.json', help='output file path in JSON format')
args = parser.parse_args()

protocols_db = {}

def run(emulator, target, nvram, **kwargs):
    try:
        output = subprocess.run(f'{emulator} -v -t "{target}" -n "{nvram}"', **kwargs)
    except subprocess.TimeoutExpired:
        return ""
    return str(output.stdout)

def get_protocols(emulator, target, nvram):
    commands = (
        b'c\n'               # Continue, finish execution
        b'info protocols\n'  # Display information about installed protocols
        b'q\n'               # Quit
    )

    output = run(emulator, target, nvram, input=commands, capture_output=True, timeout=10)
    return re.findall("GUID: (.{8}-.{4}-.{4}-.{4}-.{12})", output)

def show_item(item):
    return f'Emulating: {item}'

modules = glob.glob(os.path.join(args.directory, "*"))
with click.progressbar(modules,
                       label='Modules analysis',
                       item_show_func=show_item) as bar:
    for target in bar:
        for proto in get_protocols(args.emulator, target, args.nvram):
            if protocols_db.get(proto) is None:
                protocols_db[proto] = [target]
            else:
                protocols_db[proto].append(target)

with open(args.output, "w") as f:
    json.dump(protocols_db, f, indent=2)
    