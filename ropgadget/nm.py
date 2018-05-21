import collections
import re
import sys
from subprocess import *


linedata = re.compile('([0-9a-f]+)\s+(\w)\s+(\w+)', re.IGNORECASE)



def fetchLines(args):
    proc = 0
    try:
        proc = Popen(args, stdout=PIPE)
    except OSError as e:
        if e.errno != 2:
            raise Exception("fetchLines: OS error({0}): {1}".format(e.errno, e.strerror))
        return None
    output = proc.communicate()[0]
    if proc.returncode != 0:
        print'{0} failed. Is it installed on your machine?'.format(args[0])
        return None
    return output.splitlines(False)



def doNM(executable):
    fns = collections.OrderedDict()
    addrs = []
    intervals = []
    previous = None
    mapping = collections.OrderedDict()
    nmCmd  = ['nm', '-a', '-n',  executable]
    lines = fetchLines(nmCmd)
    for line in lines:
        m = linedata.match(line)
        if m:
            addr = m.group(1)
            typ = m.group(2)
            sym = m.group(3)
            if addr != '0' * 16:
                addr_int = int(addr, 16)
                if previous is not None:
                    intervals.append([previous, addr_int])
                previous = addr_int
                mapping[addr_int] = (addr, sym, typ)
                addrs.append('0x' + addr)
                fns[sym] = 0
    return (fns, intervals, addrs, mapping)




class Functions(object):
    def __init__(self, core, gadgets, options):
        self.__core = core
        self.__gadgets = gadgets
        self.__options = options
        (self.__fns, self.__intervals, self.__addrs, self.__map) = doNM(self.__options.binary)


    def show(self):
        for gadget in self.__gadgets:
            quad = self.getFunction(gadget)
            if quad is not None:
                (addr, sym, typ) = quad
                self.__fns[sym] += 1
            #print("vaddr = {0} : {1}\n".format(gadget["vaddr"], sym))
        for key in self.__fns:
            count = self.__fns[key]
            if count > 0:
                print("\n{0} has {1} gadgets".format(key, count))
        print("\n")

    def getFunction(self, gadget):
        function = None
        vaddr = gadget["vaddr"]
        for interval in self.__intervals:
            if interval[0] <= vaddr and vaddr < interval[1]:
                function = self.__map[interval[0]]
                break
        return function




def main(args):
    success = doNM(args[1])
    print(success)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
