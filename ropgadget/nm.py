import collections
import re
import sys
import json
import operator

from subprocess import *


linedata = re.compile('([0-9a-f]+)\s+(\w)\s+_?(\w+)', re.IGNORECASE)



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


#  llvm-nm -print-armap  is the mac os x equivalent (otool has removed the functionality.)
def doNM(executable):
    addrs = []
    intervals = []
    previous = None
    mapping = collections.OrderedDict()
    nmCmd  = ['nm', '-C', '-a', '-n',  executable]
    lines = fetchLines(nmCmd)
    for line in lines:
        m = linedata.match(line)
        if m:
            addr = m.group(1)
            typ = m.group(2)
            sym = m.group(3)
            addr_int = int(addr, 16)
            if addr_int != 0:
                if previous is not None:
                    intervals.append([previous, addr_int])
                previous = addr_int
                mapping[addr_int] = (addr, sym, typ)
                addrs.append('0x' + addr)
    intervals.append([previous, None])  #the last one
    return (intervals, addrs, mapping)




class Functions(object):
    def __init__(self, core, gadgets, options):
        self.__core = core
        self.__gadgets = gadgets
        self.__options = options
        self.__fns = {}
        (self.__intervals, self.__addrs, self.__map) = doNM(self.__options.binary)
        for gadget in self.__gadgets:
            quad = self.getFunction(gadget)
            if quad is not None:
                (addr, sym, typ) = quad
                if sym in self.__fns:
                    self.__fns[sym] += 1
                else:
                    self.__fns[sym] = 1

    def show(self):
            #print("vaddr = {0} : {1}\n".format(gadget["vaddr"], sym))
        for key in self.__fns:
            count = self.__fns[key]
            if count > 0:
                print("{0} has {1} gadgets".format(key, count))
        print("\n")

    def map(self):
        path = self.__options.fns2map
        data = self.__fns
        with open(path, 'w') as fp:
            json.dump(data, fp)
        print("Wrote {0} entries out to {1}\n".format(len(data), path))

    def list(self):
        path = self.__options.fns2list
        data = sorted(self.__fns.items(), key=operator.itemgetter(1), reverse=True)
        with open(path, 'w') as fp:
            json.dump(data, fp)
        print("Wrote {0} entries out to {1}\n".format(len(data), path))

    def lines(self):
        path = self.__options.fns2lines
        data = sorted(self.__fns.items(), key=operator.itemgetter(1), reverse=True)
        with open(path, 'w') as fp:
            for d in data:
                fp.write("{0} {1}\n".format(d[0], d[1]))
        print("Wrote {0} entries out to {1}\n".format(len(data), path))


    def getFunction(self, gadget):
        function = None
        vaddr = gadget["vaddr"]
        for interval in self.__intervals:
            if interval[0] <= vaddr:
                if interval[1] is None or vaddr < interval[1]:
                    function = self.__map[interval[0]]
                    break
        return function

    def getMap(self, copy=True):
        if copy:
            retval = {}
            retval.update(self.__fns)
            return retval
        else:
            return self.__fns


def main(args):
    success = doNM(args[1])
    print(success)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
