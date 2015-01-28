#protocol fuzzer control mechanism.

#TODO:  WORK ON RECEIVE FIRST PROTOCOLS

#imports
import os
import socket
import imp
import sys

original_stdout = sys.stdout
original_stderr = sys.stderr

def print_to_screen(func):
    def decorator(self, *args):
        tmpout = sys.stdout
        tmperr = sys.stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        restore_stdout = func(self, *args)
        if restore_stdout:
            sys.stdout = tmpout
            sys.stderr = tmperr
    return decorator

#fuzzer parent class
class Fuzzer(object):
    
    def __init__(self, protocol='rdp'):
        self.protocol = protocol
        self._target = None
        self._path = None
        self._template_type = None
        self._port = None
        self._transport = None
        self._errorClass = None
        self._log = False
        self._log_file = 'stdout'
        self._stdout = sys.stdout
        self._stderr = sys.stderr
        
    def terminate(self):
        print 'Fuzzer Object Complete, terminating...'
        try:
            self.stdout_fh.close()
        except:
            pass
        sys.stdout = original_stdout
        sys.stderr = original_stderr
            
    @property
    def target(self):
        return self._target or '127.0.0.1'
    
    @target.setter
    def target(self, value):
        self._target = value
        
    @property
    def path(self):
        return self._path or '.'
    
    @path.setter
    def path(self, value):
        self._path = value
        
    @property
    def template_type(self):
        return self._template_type or '.template.rdp'
    
    @template_type.setter
    def template_type(self, value):
        self._template_type = value
        
    @property
    def port(self):
        return self._port or 3389
    
    @port.setter
    def port(self, value):
        self._port = value
        
    @property
    def transport(self):
        return self._transport or 'TCP'
    
    @transport.setter
    def transport(self, value):
        self._transport = value.upper()
        
    @property
    def errorClass(self):
        return self._errorClass or 'RDPError'
    
    @errorClass.setter
    def errorClass(self, value):
        self._errorClass = value
    
    @property
    @print_to_screen
    def log(self):
        if self._log == False and sys.stdout == self._stdout:
            print 'Logging to stdout.'
        elif self._log == False and sys.stdout != self._stdout:
            print 'Logging is configured for stdout but a file is specified, please confirm configuration.'
        elif self._log == True and sys.stdout == self._stdout:
            print 'Logging is configured for a file but filename not yet set, please configure log_file.'
        elif self._log == True and sys.stdout != self._stdout:
            print 'Logging is configured for file %s.' % self._log_file
        return True
            
    @log.setter
    @print_to_screen
    def log(self, value):
        if value == False:
            self._log = False
            sys.stdout = self._stdout
            sys.stderr = self._stderr
        else:
            self._log = True
            print 'Logging set to use file, please configure log_file to specify file output.'
        return True
            
    
    @property
    @print_to_screen
    def log_file(self):
        if self._log_file == 'stdout':
            print 'Currently logging to stdout, no file configured.'
        else:
            print 'Configured to log to file: %s.' % self._log_file
        return True
    
    @log_file.setter
    @print_to_screen
    def log_file(self, value):
        self._log_file = value
        if self._log_file == 'stdout':
            sys.stdout = self._stdout
            sys.stderr = self._stderr
        else:
            try:
                self.stdout_fh = open(self._log_file, 'w')
                print 'Logging to %s' % self._log_file
            except Exception, msg:
                print 'Error Message: %s' % msg
                print 'Please select a new log location.'
            sys.stdout = self.stdout_fh
            sys.stderr = self.stdout_fh
        return False
    
    
    def find_templates(self):
        all_templates = []
        #load template files from configuration directory
        for filename in os.listdir(self.path):
            if filename.endswith(self.template_type):
                all_templates.append(os.path.join(self.path, filename))
        
        return all_templates
            

    def run(self):
        self.protocol_module = imp.load_source(self.protocol, './' + self.protocol + '.py')
        self.error_module = imp.load_source(self.protocol + '_error', './' + self.protocol + '_error.py')
        self.raised_error = getattr(self.error_module, self.errorClass)
        all_templates = self.find_templates()
        for template in all_templates:
            self.template = template
            self.current_template = imp.load_source('current_template', template)
            try:
                self.connect()
            except socket.error:
                print '================'
                print 'Error Connecting to %s:%s with template - %s' % (self.target, self.port, self.template)
                continue
            self.fuzz()
        self.terminate()
            
    
    def fuzz(self):
        try:
            this = getattr(self.protocol_module, str(self.protocol.upper()))()
            this.start(self.s, self.current_template)
            print '================'
        except self.raised_error as err:
            print 'Exception Raised on Template - %s' % self.template
            print 'Error Code: %s' % err.err_code
            print 'Error Name: %s' % err.err_name
            print 'Error Description: %s' % err.err_desc
            return -1
        except socket.error:
            print 'Socket Error Raised with template - %s' % self.template
            return -1
        print 'Current Template Completed Successfully - %s' % self.template
        return 0
        
    def connect(self):
        self.s = Socket(self.target, self.port, self.transport)
        self.s.open()

            

        
class RDPFuzzer(Fuzzer):
    
    def __init__(self, target = '127.0.0.1'):
        super(RDPFuzzer, self).__init__(protocol='rdp')
        self.template_type = '.template.rdp'
        self.path = './rdp_templates'
        self.port = 3389
        self.transport = 'TCP'
        self.target = target
        self.errorClass = 'RDPError'
        
        
class HTTPFuzzer(Fuzzer):
    
    def __init__(self, target):
        super(HTTPFuzzer, self).__init__(protocol='http')
        self.template_type = '.template.http'
        self.path = './http_templates'
        self.port = 80
        self.transport = 'TCP'
        self.target = target
        self.errorClass = 'HTTPError'
        
        
        

class Socket(object):
    
    def __init__(self, host, port, transport):
        self._target = host
        self._port = port
        self._transport = transport
        self._buffer = ''
        
    def open(self):
        if self._transport == 'UDP':
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((self._target, self._port))
            
    def send(self, data):
        self._socket.send(data)
        
    def read(self):
        self._buffer = self._socket.recv(4096)
        return self._buffer
    
    def stream(self):
        self._stream_buffer = ''
        while True:
            try:
                self._stream_buffer += self.read()
            except socket.error:
                break
        return self._stream_buffer
    
    def limited_stream(self, counter):
        self._stream_buffer = ''
        while counter > 0:
            try:
                self._stream_buffer += self.read()
            except socket.error:
                break
            counter -= 1
        return self._stream_buffer
    
    def clear(self):
        self._buffer = ''
        
    def close(self):
        self._socket.close()
        
        