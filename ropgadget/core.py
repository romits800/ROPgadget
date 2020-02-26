## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-17 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import cmd
import os
import re
import codecs
import ropgadget.rgutils as rgutils
import sqlite3

from ropgadget.binary             import Binary
from capstone                     import CS_MODE_32
from ropgadget.gadgets            import Gadgets
from ropgadget.options            import Options
from ropgadget.ropchain.ropmaker  import ROPMaker
from ropgadget.nm                 import Functions
from collections import defaultdict


def resolve_datafile(name):
    """ returns the absolute path to the data file included in *this* directory.
    """

    data="data/"
    path = os.path.join(os.path.dirname(__file__), data)
    path=path+name
    return path if os.path.exists(path) else None


class Core(cmd.Cmd):

    classes = resolve_datafile('classes.txt')
    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options   = options
        self.__binary    = None
        self.__gadgets   = []
        self.__offset    = 0
        self.__functions = None
        self.prompt      = '(ROPgadget)> '


    def __checksBeforeManipulations(self):
        if self.__binary == None or self.__binary.getBinary() == None or self.__binary.getArch() == None or self.__binary.getArchMode() == None:
            return False
        return True

    def _sectionInRange(self, section):
        """
        given a section and a range, edit the section so that all opcodes are within the range
        """
        if self.__options.range == "0x0-0x0":
            return section

        rangeStart, rangeEnd = map(lambda x:int(x, 16), self.__options.range.split('-'))

        sectionStart = section['vaddr']
        sectionEnd = sectionStart + section['size']

        opcodes = section['opcodes']
        if rangeEnd < sectionStart or rangeStart > sectionEnd:
            return None
        if rangeStart > sectionStart:
            diff = rangeStart - sectionStart
            opcodes = opcodes[diff:]
            section['vaddr'] += diff
            section['offset'] += diff
            section['size'] -= diff
        if rangeEnd < sectionEnd:
            diff = sectionEnd - rangeEnd
            opcodes = opcodes[:-diff]
            section['size'] -= diff

        if not section['size']:
            return None
        section['opcodes'] = opcodes
        return section

    def __getGadgets(self):
        if self.__checksBeforeManipulations() == False:
            return False

        G = Gadgets(self.__binary, self.__options, self.__offset)
        execSections = self.__binary.getExecSections()

        # Find ROP/JOP/SYS gadgets
        self.__gadgets = []
        for section in execSections:
            section = self._sectionInRange(section)
            if not section: continue
            if not self.__options.norop: self.__gadgets += G.addROPGadgets(section)
            if not self.__options.nojop: self.__gadgets += G.addJOPGadgets(section)
            if not self.__options.nosys: self.__gadgets += G.addSYSGadgets(section)

        # Pass clean single instruction and unknown instructions
        self.__gadgets = G.passClean(self.__gadgets, self.__options.multibr)

        # Delete duplicate gadgets
        if not self.__options.all:
            self.__gadgets = rgutils.deleteDuplicateGadgets(self.__gadgets)

        # Applicate some Options
        self.__gadgets = Options(self.__options, self.__binary, self.__gadgets).getGadgets()

        # Sorted alphabetically
        self.__gadgets = rgutils.alphaSortgadgets(self.__gadgets)

        return True

    def __default_to_regular(self,d):
        if isinstance(d, defaultdict):
            d = {k: self.__default_to_regular(v) for k, v in d.items()}
        return d

    def __makingclasses(self):
        ##Read from the current file
        if Core.classes is None:
            print('classes.txt datafile not found, sorry.')
            return
        single_byte_ins = ["leave","clc","aaa","sahf","daa","aas","das","lahf"]
        recursivedict=lambda:defaultdict(recursivedict)
        gadgetclasses=recursivedict()
        with codecs.open(Core.classes,'r','utf-8') as fp:
            for line in fp:
                line.strip()
                if not line:
                    break
                if line.split(' ',1)[0]=="classname":
                   classname=line.split(' ',1)[1].strip()
                else:
                    instruction=line
                    instruction=instruction.strip()
                    instruction=instruction.split(',',1)
                    firstpart=instruction[0].strip()
                    opcode=firstpart.split(' ',1)[0]
                    if opcode in single_byte_ins: # for single instructions with no operands
                        try:
                            lists=gadgetclasses[opcode]
                        except:
                            pass
                        finally:
                            if not lists:
                                gadgetclasses[opcode]=[classname]
                            else:
                                if classname not in lists:
                                    lists.append(classname)
                        continue

                    operand1=firstpart.partition(' ')[2].strip()
                    operand2=""
                    if len(instruction)>1:
                        operand2=instruction[1].strip()
                    if operand2!="":#for instructions with two operands
                        lists=[]
                        try:
                            lists=gadgetclasses[opcode][operand1][operand2]
                        except:
                            pass
                        finally:
                            if not lists:
                                gadgetclasses[opcode][operand1][operand2]=[classname]
                            else:
                                if classname not in lists:
                                    lists.append(classname)
                    else: #for instructions with one operand
                        lists=[]
                        try:
                            lists=gadgetclasses[opcode][operand1]
                        except:
                            pass
                        finally:
                            if not lists:
                                gadgetclasses[opcode][operand1]=[classname]
                            else:
                                if classname not in lists:
                                    lists.append(classname)


        gadgetclasses=self.__default_to_regular(gadgetclasses)
    #    print gadgetclasses
        return gadgetclasses

    def __lookingForGadgets(self):

        if self.__checksBeforeManipulations() == False:
            return False

        if self.__options.silent:
            return True

        arch = self.__binary.getArchMode()
        print("Gadgets information\n============================================================")
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts=  gadget["gadget"]
            bytes = gadget["bytes"]
            bytesStr = " // " + bytes.encode('hex') if self.__options.dump else ""
            print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(insts) + bytesStr)
        #self.__makingclasses()
        print("\nUnique gadgets found: %d" %(len(self.__gadgets)))
        return True


    def __checkingForClasses(self):

        if self.__checksBeforeManipulations() == False:
            return False

        if self.__options.silent:
            return True
        classes = self.__makingclasses()
        class_ins = {}
        arch = self.__binary.getArchMode()
        print("Gadgets information\n============================================================")
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            bytes = gadget["bytes"]
            bytesStr = " // " + bytes.encode('hex') if self.__options.dump else ""
            splited_ins =  insts.split(' ; ')
            single_ins = splited_ins[:-1]
            if(len(single_ins)==1 and (splited_ins[-1][0]=='r')):
                separated_ins  = single_ins[0].split(" ",1)
                opcode = separated_ins[0]
                if(len(separated_ins) == 2):
                    arguments = separated_ins[1].split(", ")
                elif(len(separated_ins)==1):
                    arguments = []
                try:
                    data = classes[opcode]
                    for i in arguments:
                        data = data[i]
                    for j in data:
                        try:
                            class_ins[j].append({u'addr' : vaddr, u'ins' : insts + bytesStr,u'arch' : arch })
                        except:
                            class_ins[j] = [{u'addr' : vaddr, u'ins' : insts + bytesStr, u'arch':arch}]
                except:
                    continue;
        for cls in class_ins.keys():
            print "\n===========================================================\n",cls, "\n==========================================================="
            for ins in class_ins[cls]:
                print(("0x%08x" %(ins["addr"]) if ins["arch"] == CS_MODE_32 else "0x%016x" %(ins["addr"])) + " : %s" %(ins["ins"]))


        print "\n",len(class_ins.keys()), "Classes Satisfied"
        print("\nUnique gadgets found: %d" %(len(self.__gadgets)))
        return True


    def __lookingForAString(self, string):

        if self.__checksBeforeManipulations() == False:
            return False

        if self.__options.silent:
            return True

        dataSections = self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print("Strings information\n============================================================")
        for section in dataSections:
            section = self._sectionInRange(section)
            if not section: continue
            allRef = [m.start() for m in re.finditer(string.encode(), section["opcodes"])]
            for ref in allRef:
                vaddr  = self.__offset + section["vaddr"] + ref
                match = section["opcodes"][ref:ref+len(string)]
                print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(match.decode()))
        return True


    def __lookingForOpcodes(self, opcodes):

        if self.__checksBeforeManipulations() == False:
            return False

        if self.__options.silent:
            return True

        execSections = self.__binary.getExecSections()
        arch = self.__binary.getArchMode()
        print("Opcodes information\n============================================================")
        for section in execSections:
            section = self._sectionInRange(section)
            if not section: continue
            allRef = [m.start() for m in re.finditer(re.escape(opcodes.decode("hex")), section["opcodes"])]
            for ref in allRef:
                vaddr  = self.__offset + section["vaddr"] + ref
                print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(opcodes))
        return True


    def __lookingForMemStr(self, memstr):

        if self.__checksBeforeManipulations() == False:
            return False

        if self.__options.silent:
            return True

        sections  = self.__binary.getExecSections()
        sections += self.__binary.getDataSections()
        arch = self.__binary.getArchMode()
        print("Memory bytes information\n=======================================================")
        chars = list(memstr)
        for char in chars:
            try:
                for section in sections:
                    section = self._sectionInRange(section)
                    if not section: continue
                    allRef = [m.start() for m in re.finditer(char, section["opcodes"])]
                    for ref in allRef:
                        vaddr  = self.__offset + section["vaddr"] + ref
                        print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : '%c'" %(char))
                        raise
            except:
                pass
        return True

    def analyze(self):
        try:
            self.__offset = int(self.__options.offset, 16) if self.__options.offset else 0
        except ValueError:
            print("[Error] The offset must be in hexadecimal")
            return False
        if self.__options.console:
            if self.__options.binary:
                self.__binary = Binary(self.__options)
                if self.__checksBeforeManipulations() == False:
                    return False
            self.cmdloop()
            return True

        self.__binary = Binary(self.__options)
        if self.__checksBeforeManipulations() == False:
            return False

        if   self.__options.string:   return self.__lookingForAString(self.__options.string)
        elif self.__options.opcode:   return self.__lookingForOpcodes(self.__options.opcode)
        elif self.__options.memstr:   return self.__lookingForMemStr(self.__options.memstr)
        else:
            self.__getGadgets()
            if(self.__options.microgadgets):
                self.__checkingForClasses()
        #    print self.__options
            else:
                self.__lookingForGadgets()
            if self.__options.ropchain:
                ROPMaker(self.__binary, self.__gadgets, self.__offset)
            elif self.__options.fns:
                arch = self.__binary.getArchMode()
                if arch != CS_MODE_32:
                    self.functions().show()
                else:
                    print("Not implemented on 32 bit yet.")
            elif self.__options.fns2map:
                arch = self.__binary.getArchMode()
                if arch != CS_MODE_32:
                    self.functions().map()
                else:
                    print("Not implemented on 32 bit yet.")
            elif self.__options.fns2list:
                arch = self.__binary.getArchMode()
                if arch != CS_MODE_32:
                    self.functions().list()
                else:
                    print("Not implemented on 32 bit yet.")
            elif self.__options.fns2lines:
                arch = self.__binary.getArchMode()
                if arch != CS_MODE_32:
                    self.functions().lines()
                else:
                    print("Not implemented on 32 bit yet.")
            return True


    def gadgets(self):
        return self.__gadgets


    def functions(self):
        return Functions(self, self.__gadgets, self.__options)

    # Console methods  ============================================

    def do_fns(self):
        if self.__binary == None:
            if not silent:
                print("[-] No binary loaded.")
            return False
        Functions(self, self.__options).show()
        return False

    def do_binary(self, s, silent=False):
        # Do not split the filename with spaces since it might contain
        # whitespaces
        if len(s) == 0:
            if not silent:
                return self.help_binary()
            return False

        binary = s

        self.__options.binary = binary
        self.__binary = Binary(self.__options)
        if self.__checksBeforeManipulations() == False:
            return False

        if not silent:
            print("[+] Binary loaded")


    def help_binary(self):
        print("Syntax: binary <file> -- Load a binary")
        return False


    def do_EOF(self, s, silent=False):
        return self.do_quit(s, silent)

    def do_quit(self, s, silent=False):
        return True


    def help_quit(self):
        print("Syntax: quit -- Terminates the application")
        return False


    def do_load(self, s, silent=False):

        if self.__binary == None:
            if not silent:
                print("[-] No binary loaded.")
            return False

        if not silent:
            print("[+] Loading gadgets, please wait...")
        self.__getGadgets()

        if not silent:
            print("[+] Gadgets loaded !")


    def help_load(self):
        print("Syntax: load -- Load all gadgets")
        return False


    def do_display(self, s, silent=False):
        self.__lookingForGadgets()


    def help_display(self):
        print("Syntax: display -- Display all gadgets loaded")
        return False


    def do_depth(self, s, silent=False):
        try:
            depth = int(s.split()[0])
        except:
            if not silent:
                return self.help_depth()
            return False
        if depth <= 0:
            if not silent:
                print("[-] The depth value must be > 0")
            return False
        self.__options.depth = int(depth)

        if not silent:
            print("[+] Depth updated. You have to reload gadgets")


    def help_depth(self):
        print("Syntax: depth <value> -- Set the depth search engine")
        return False


    def do_badbytes(self, s, silent=False):
        try:
            bb = s.split()[0]
        except:
            if not silent:
                return self.help_badbytes()
            else:
                return False
        self.__options.badbytes = bb

        if not silent:
            print("[+] Bad bytes updated. You have to reload gadgets")


    def help_badbytes(self):
        print("Syntax: badbytes <badbyte1|badbyte2...> -- ")
        return False


    def __withK(self, listK, gadget):
        if len(listK) == 0:
            return True
        for a in listK:
            if a not in gadget:
                return False
        return True

    def __withoutK(self, listK, gadget):
        for a in listK:
            if a in gadget:
                return False
        return True

    def do_search(self, s, silent=False):
        args = s.split()
        if not len(args):
            return self.help_search()
        withK, withoutK = [], []
        for a in args:
            if a[0:1] == "!":
                withoutK += [a[1:]]
            else:
                withK += [a]
        if self.__checksBeforeManipulations() == False:
            if not silent:
                print("[-] You have to load a binary")
            return False
        arch = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            if self.__withK(withK, insts) and self.__withoutK(withoutK, insts):
                # What to do if silent = True?
                print(("0x%08x" %(vaddr) if arch == CS_MODE_32 else "0x%016x" %(vaddr)) + " : %s" %(insts))


    def help_search(self):
        print("Syntax: search <keyword1 keyword2 keyword3...> -- Filter with or without keywords")
        print("keyword  = with")
        print("!keyword = witout")
        return False


    def count(self):
        return len(self.__gadgets)

    def do_count(self, s, silent=False):
        if not silent:
            print("[+] %d loaded gadgets." % self.count())


    def help_count(self):
        print("Shows the number of loaded gadgets.")
        return False


    def do_filter(self, s, silent=False):
        try:
            self.__options.filter = s.split()[0]
        except:
            if not silent:
                return self.help_filter()
            return False

        if not silent:
            print("[+] Filter setted. You have to reload gadgets")


    def help_filter(self):
        print("Syntax: filter <filter1|filter2|...> - Suppress specific instructions")
        return False


    def do_only(self, s, silent=False):
        try:
            if s.lower() == "none":
                self.__options.only = None
            else:
                self.__options.only = s.split()[0]
        except:
            if not silent:
                return self.help_only()
            return False

        if not silent:
            print("[+] Only setted. You have to reload gadgets")


    def help_only(self):
        print("Syntax: only <only1|only2|...> - Only show specific instructions")
        return False


    def do_range(self, s, silent=False):
            try:
                rangeS = int(s.split('-')[0], 16)
                rangeE = int(s.split('-')[1], 16)
                self.__options.range = s.split()[0]
            except:
                if not silent:
                    return self.help_range()
                return False

            if rangeS > rangeE:
                if not silent:
                    print("[-] The start value must be greater than the end value")
                return False

            if not silent:
                print("[+] Range setted. You have to reload gadgets")


    def help_range(self):
        print("Syntax: range <start-and> - Search between two addresses (0x...-0x...)")
        return False


    def do_settings(self, s, silent=False):
        print("All:         %s" %(self.__options.all))
        print("Badbytes:    %s" %(self.__options.badbytes))
        print("Binary:      %s" %(self.__options.binary))
        print("Depth:       %s" %(self.__options.depth))
        print("Filter:      %s" %(self.__options.filter))
        print("Memstr:      %s" %(self.__options.memstr))
        print("MultiBr:     %s" %(self.__options.multibr))
        print("NoJOP:       %s" %(self.__options.nojop))
        print("NoROP:       %s" %(self.__options.norop))
        print("NoSYS:       %s" %(self.__options.nosys))
        print("Offset:      %s" %(self.__options.offset))
        print("Only:        %s" %(self.__options.only))
        print("Opcode:      %s" %(self.__options.opcode))
        print("ROPchain:    %s" %(self.__options.ropchain))
        print("Range:       %s" %(self.__options.range))
        print("RawArch:     %s" %(self.__options.rawArch))
        print("RawMode:     %s" %(self.__options.rawMode))
        print("Re:          %s" %(self.__options.re))
        print("String:      %s" %(self.__options.string))
        print("Thumb:       %s" %(self.__options.thumb))

    def help_settings(self):
        print("Display setting's environment")
        return False


    def do_nojop(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_nojop()

        if arg == "enable":
            self.__options.nojop = True
            if not silent:
                print("[+] NoJOP enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.nojop = False
            if not silent:
                print("[+] NoJOP disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_nojop()
            return False


    def help_nojop(self):
        print("Syntax: nojop <enable|disable> - Disable JOP search engin")
        return False


    def do_norop(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_norop()

        if arg == "enable":
            self.__options.norop = True
            if not silent:
                print("[+] NoROP enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.norop = False
            if not silent:
                print("[+] NoROP disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_norop()
            return False


    def help_norop(self):
        print("Syntax: norop <enable|disable> - Disable ROP search engin")
        return False


    def do_nosys(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_nosys()

        if arg == "enable":
            self.__options.nosys = True
            if not silent:
                print("[+] NoSYS enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.nosys = False
            if not silent:
                print("[+] NoSYS disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_nosys()

            return False


    def help_nosys(self):
        print("Syntax: nosys <enable|disable> - Disable SYS search engin")
        return False


    def do_thumb(self, s, silent=False):
        try:
            arg = s.split()[0]
        except:
            return self.help_thumb()

        if arg == "enable":
            self.__options.thumb = True
            if not silent:
                print("[+] Thumb enable. You have to reload gadgets")

        elif arg == "disable":
            self.__options.thumb = False
            if not silent:
                print("[+] Thumb disable. You have to reload gadgets")

        else:
            if not silent:
                return self.help_thumb()
            return False


    def help_thumb(self):
        print("Syntax: thumb <enable|disable> - Use the thumb mode for the search engine (ARM only)")
        return False


    def do_all(self, s, silent=False):
        if s == "enable":
            self.__options.all = True
            if not silent:
                print("[+] Showing all gadgets enabled. You have to reload gadgets")

        elif s == "disable":
            self.__options.all = False
            if not silent:
                print("[+] Showing all gadgets disabled. You have to reload gadgets")

        else:
            if not silent:
                return self.help_all()

            return False


    def help_multibr(self):
        print("Syntax: multibr <enable|disable> - Enable/Disable multiple branch gadgets")
        return False


    def do_multibr(self, s, silent=False):
        if s == "enable":
            self.__options.multibr = True
            if not silent:
                print("[+] Multiple branch gadgets enabled. You have to reload gadgets")

        elif s == "disable":
            self.__options.multibr = False
            if not silent:
                print("[+] Multiple branch gadgets disabled. You have to reload gadgets")

        else:
            if not silent:
                return self.help_all()

            return False


    def help_all(self):
        print("Syntax: all <enable|disable - Show all gadgets (disable removing duplicate gadgets)")
        return False


    def help_re(self):
        print("Syntax: re <pattern1 | pattern2 |...> - Regular expression")
        return False


    def do_re(self, s, silent=False):
        if s.lower() == 'none':
            self.__options.re = None
        elif s == "":
            self.help_re()
            silent = True
        else:
            self.__options.re = s

        if not silent:
            print("[+] Re setted. You have to reload gadgets")
