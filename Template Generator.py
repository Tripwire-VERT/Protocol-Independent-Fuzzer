#################################################################
# Generates Template files for fuzzer.py
# Does a couple things so far
# 1. flips bytes
# 2. minimizes and maximizes values
# TODO add more functionality and ways to fuzz.
#################################################################

import re
import os
import sys
import struct
from optparse import OptionParser


template = open('test.template.rdp', 'r').read()

t_spit = template.split('\ndef')[1:]

template_dict = dict()

def resolveArgs():
    '''resolve the input args'''
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option('--max',   dest='max', type='string', help='The amount of fuzzed packets.')
    (opts, args) = parser.parse_args()
    
    return opts

def remove_white_space(data):
    variable_white_space = re.findall('\' +\+ +\'', data)
    for space in variable_white_space:
        data = data.replace(space,'').replace('\' + \'', '')
    return data


def parse_field(data, field):
    data = data[data.find(field):]
    data_variable = data[:data.find('=')].strip()
    data_var_values = data[data.find('['):data.find(']')+1]
    return data_var_values

def grab_default_values(data, variables):
    variable_dict = dict()
    for variable in variables:
        test = re.search('%s += (.+)' % variable, data)
        variable_dict[variable] = remove_white_space(test.group(1))
    return variable_dict

def end_of_function(data, variables):
    data = data[data.find('length_fields'):]
    data = data[data.find('\n'):]
    data = data[data.find('%s ' %variables[-1]):]
    data = data[data.find('\n'):]
    return data

def list_2_dict(variables_length):
    temp = dict()
    for x in variables_length:
        temp[x[0]] = x[1]
    return temp


for x in t_spit:
    function_name       = 'def%s' % x[:x.find(':')+1]
    template_dict[function_name] = dict()
    variables           = parse_field(x.replace(' \\\n', ''), 'variables')
    variables_length    = parse_field(x.replace(' \\\n', ''), 'variables_length')
    length_fields       = parse_field(x.replace(' \\\n', ''), 'length_fields')
    
    
    exec '%s = %s' % ('variables',variables)
    exec '%s = %s' % ('variables_length',variables_length)
    exec '%s = %s' % ('length_fields',length_fields)
    
    variables_length = list_2_dict(variables_length)
    
    default_values = grab_default_values(x.replace(' \\\n', ''), variables)
    default_values['variables'] = variables
    default_values['variables_length'] = variables_length
    default_values['length_fields'] = length_fields
    default_values['build'] = end_of_function(x, variables)
    
    template_dict[function_name] = default_values

packets = ['def generateX224Request():', 'def generateErectDomain():', 'def generateMCSAttachUser():', 'def channelJoinRequest(channel):', 'def generateMCSRequest( encryption_type = 16):', 'def createClientInfo():', 'def confirmActive():', 'def macSignature(crypto, data):']


def flip_byte(f_bytes):
    if len(f_bytes) == 1:
        byte_val = 0xFF
        byte_len = 'B'
    elif len(f_bytes) == 2:
        byte_val = 0xFFFF
        byte_len = 'H'
    elif len(f_bytes) == 4:
        byte_val = 0xFFFFFFFF
        byte_len = '>L'
    
    byte_value = byte_val - struct.unpack(byte_len, f_bytes)[0]
    flipped = struct.pack(byte_len, byte_value)
    return flipped

def byte_flip(f_bytes, adding, var):
    flip_b_dict = dict()
    count = 0
    temp = []
    while (count <= len(f_bytes)-adding) and len(f_bytes) >= adding:
        temp_byte = f_bytes[count:count+adding]
        temp.append('%s%s%s' % (f_bytes[:count], flip_byte(temp_byte), f_bytes[count+adding:]))
        count += adding
    if len(temp) > 0:
        flip_b_dict[var] = temp
    else:
        flip_b_dict[var] = None
    
    return flip_b_dict

def fuzz_variable(packet, var, p_dict):
    try:
        exec '%s = %s' % ('p_var',p_dict[packet][var])
        # need to parse the packet and flip bits, bytes and endianess
        flip_b_1_dict = byte_flip(p_var, 1, var)
        flip_b_2_dict = byte_flip(p_var, 2, var)
        flip_b_4_dict = byte_flip(p_var, 4, var)
        min_max_dict = min_max(len(p_var), var)
        build_packet(packet, flip_b_1_dict, p_dict, '1_byte')
        build_packet(packet, flip_b_2_dict, p_dict, '2_byte')
        build_packet(packet, flip_b_4_dict, p_dict, '4_byte')
        build_packet(packet, min_max_dict, p_dict, 'min_max')
    except NameError:
        exec '%s = %s' % ('l_var',p_dict[packet]['variables_length'])
        min_max_dict = min_max(l_var[var], var)
        build_packet(packet, min_max_dict, p_dict, 'min_max')
    return 0

def get_original(packet_name, p_dict):
    packets = []
    for packet in p_dict:
        con_packet = []
        if packet == packet_name:
            continue
        con_packet.append(packet)
        for var in p_dict[packet]['variables']:
            con_packet.append('    %s = %s' % (var, p_dict[packet][var]))
        f_packet = '\n'.join(con_packet) + p_dict[packet]['build']
        packets.append(f_packet)
    return '\n'.join(packets)

def min_max(len_var, var, both = True, value = ''):
    min_max = dict()
    temp = ['\x00' * len_var, '\xff' * len_var]
    min_max[var] = temp
    return min_max


def build_packet(packet_name, f_dict, p_dict, version):
    vars = p_dict[packet_name]['variables']
    count = 0
    packets = get_original(packet_name, p_dict)
    for var in f_dict:
        try:
            for x in f_dict[var]:
                temp  = ''
                con_packet = []
                con_packet.append(packet_name)
                for vars in variables:
                    if vars == var:
                        con_packet.append('    %s = %s' % (vars, repr(x)))
                    else:
                        con_packet.append('    %s = %s' % (vars, p_dict[packet_name][vars]))
                packet = '\n'.join(con_packet) + p_dict[packet_name]['build']
                count += 1
                temp = 'import struct\n' + packets + '\n\n' +  packet
                write_packet_2_disk(packet_name, temp, version, var, count)
        except TypeError:
            continue

def write_packet_2_disk(packet_name, packet, version, var, count):
    f_name = packet_name.replace('def ', '').replace('():', '').strip()
    dir = 'rdp_templates'
    if not((os.path.isdir(dir))):
        os.mkdir(dir)
    print '%s_%s_%s.txt' % (var, version, count)
    file = open('%s/%s_%s_%s.template.rdp' % (dir, var, version, count), 'wb')
    file.write(packet)

opts = resolveArgs()


for packet in packets:
    if opts.max != None:
        max_count = int(opts.max)
    else:
        max_count = 'all'
    variables = template_dict[packet]['variables']
    total_count = 0
    for var in variables:
        if max_count <= total_count:
            print exit
            sys.exit()
        fuzz_variable(packet, var, template_dict)
        total_count += 1
