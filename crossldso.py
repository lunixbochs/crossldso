import enum
import struct
from collections import namedtuple, defaultdict
from cffi import FFI

# probably both on macos and linux
PROT_NONE  = 0x00
PROT_READ  = 0x01
PROT_WRITE = 0x02
PROT_EXEC  = 0x04
PROT_ALL   = PROT_READ|PROT_WRITE|PROT_EXEC
MAP_FIXED  = 0x10

# macos-specific
MAP_PRIVATE = 0x02
MAP_ANONYMOUS = 0x1000
RTLD_NEXT = -1

ffi = FFI()
ffi.cdef(r'''
void *mmap(void *addr, size_t len, int prot, int flags, int fd, ssize_t offset);
int mprotect(void *addr, size_t len, int prot);
int munmap(void *addr, size_t len);
void *dlsym(void *handle, const char *symbol);
''')
lib = ffi.dlopen(None)

def _libc_dlsym(name):
    return lib.dlsym(ffi.cast('void *', RTLD_NEXT), name.encode('utf8'))

ALIGN = 0x1000
def align(addr, *, by=0):
    by = max(ALIGN, by)
    return (addr + (by-1)) & ~(by-1)

def mmap(addr, size, prot, *, flags=MAP_PRIVATE, fileobj=None, offset=0):
    if addr is None:
        addr = ffi.NULL
    elif addr & (ALIGN-1) or size & (ALIGN-1):
        raise MemoryError('memory mapping not aligned')
    addr = ffi.cast('void *', addr)

    if fileobj is not None:
        fd = fileobj.fileno()
    else:
        fd = -1
        flags |= MAP_ANONYMOUS

    page = lib.mmap(addr, size, prot, flags, fd, offset)
    if ffi.cast('ssize_t', page) == -1:
        raise MemoryError('failed to map memory')
    return page

def munmap(addr, size):
    if addr & (ALIGN-1) or size & (ALIGN-1):
        raise MemoryError('memory mapping not aligned')
    if lib.munmap(addr, size):
        raise MemoryError('failed to unmap memory')

def mprotect(addr, size, prot):
    if int(ffi.cast('uintptr_t', addr)) & (ALIGN-1) or size & (ALIGN-1):
        raise MemoryError('memory mapping not aligned')
    if lib.mprotect(addr, size, prot):
        raise MemoryError('failed to protect memory')

# begin ELF stuff

class Struct(struct.Struct):
    def __init__(self, name, sig, *field_names):
        super().__init__(sig)
        self.namedtuple = namedtuple(name, field_names)

    def read_from(self, f, offset=None):
        if offset is not None:
            f.seek(offset)
        return self.namedtuple(*self.unpack(f.read(self.size)))

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
EV_CURRENT = 1

class PF(enum.IntEnum):
    EXEC = 1
    WRITE = 2
    READ = 4

class PT(enum.IntEnum):
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    SHLIB = 5
    PHDR = 6
    TLS = 7
    LOOS = 0x60000000
    GNU_EH_FRAME = 0x6474e550
    GNU_STACK = 0x6474e551
    GNU_RELRO = 0x6474e552
    LOSUNW = 0x6ffffffa
    SUNWBSS = 0x6ffffffa
    SUNWSTACK = 0x6ffffffb
    HISUNW = 0x6fffffff
    HIOS = 0x6fffffff
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff

class DT(enum.IntEnum):
    NULL = 0
    NEEDED = 1
    PLTRELSZ = 2
    PLTGOT = 3
    HASH = 4
    STRTAB = 5
    SYMTAB = 6
    RELA = 7
    RELASZ = 8
    RELAENT = 9
    STRSZ = 10
    SYMENT = 11
    INIT = 12
    FINI = 13
    SONAME = 14
    RPATH = 15
    SYMBOLIC = 16
    REL = 17
    RELSZ = 18
    RELENT = 19
    PLTREL = 20
    DEBUG = 21
    TEXTREL = 22
    JMPREL = 23
    BIND_NOW = 24
    INIT_ARRAY = 25
    FINI_ARRAY = 26
    INIT_ARRAYSZ = 27
    FINI_ARRAYSZ = 28
    FLAGS = 30
    PREINIT_ARRAY = 32
    PREINIT_ARRAYSZ = 33
    LOOS = 0x60000000
    HIOS = 0x6ffff000
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff

    # GNU extensions
    GNU_HASH = 0x6ffffef5
    VERNEED = 0x6ffffffe
    VERNEEDNUM = 0x6fffffff
    VERSYM = 0x6ffffff0

class STB(enum.IntEnum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2
    LOOS = 10
    HIOS = 12
    LOPROC = 13
    HIPROC = 15

class STT(enum.IntEnum):
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    COMMON = 5
    TLS = 6
    LOOS = 10
    HIOS = 12
    LOPROC = 13
    SPARC_REGISTER = 13
    HIPROC = 15

class STV(enum.IntEnum):
    DEFAULT = 0
    INTERNAL = 1
    HIDDEN = 2
    PROTECTED = 3
    EXPORTED = 4
    SINGLETON = 5
    ELIMINATE = 6

class R_AMD64(enum.IntEnum):
    NONE = 0
    _64 = 1
    PC32 = 2
    GOT32 = 3
    PLT32 = 4
    COPY = 5
    GLOB_DAT = 6
    JUMP_SLOT = 7
    RELATIVE = 8
    GOTPCREL = 9
    _32 = 10
    _32S = 11
    _16 = 12
    PC16 = 13
    _8 = 14
    PC8 = 15
    PC64 = 24
    GOTOFF64 = 25
    GOTPC32 = 26
    SIZE32 = 32
    SIZE64 = 33

class ElfGnuHash:
    @staticmethod
    def hash(name):
        h = 5381
        for c in name.split('\0', 1)[0]:
            h = (h << 5) + h + ord(c)
        return h & 0xffffffff

    @staticmethod
    def count(data, addr):
        fmt = addr.format.decode('utf8')
        en = fmt[0]
        awords = fmt[-1]
        word = struct.Struct(en + 'I')

        u = lambda n=1, word='I': (struct.unpack_from(en + ('%d%s' % (n, word)), data), data[struct.calcsize(word) * n:])
        (nbuckets, base, bitmask_nwords, shift), data = u(4)
        bitmask, data = u(n=bitmask_nwords, word=awords)
        buckets, data = u(nbuckets)
        top = max(buckets)
        if top:
            last = top
            pos = (top - base) * word.size
            while not word.unpack(data[pos:pos+word.size])[0] & 1:
                pos += word.size
                last += 1
            return base, last
        return base, 0

class CrossElfLib:
    def __init__(self, parent):
        self._parent = parent

    def __repr__(self):
        return 'CrossElfLib({self.parent.path})'

class CrossElf64:
    class codec:
        bits = 64
        file_ident = Struct('Ident', '4sBBBBBxxxxxxx', 'magic', 'elf_class', 'elf_data', 'file_version', 'osabi', 'abi_version')
        file_header = Struct('FileHeader', '<HHIQQQIHHHHHH',
                             'type', 'machine', 'version', 'entry', 'phoff', 'shoff', 'flags', 'ehsize', 'phentsize', 'phnum', 'shentsize', 'shnum', 'shstrndx')
        section_header = Struct('SectionHeader', '<IIQQQQIIQQ',
                                'nameoff', 'type', 'flags', 'addr', 'off', 'size', 'link', 'info', 'addralign', 'entsize')
        program_header = Struct('ProgramHeader', '<IIQQQQQQ',
                                'type', 'flags', 'off', 'vaddr', 'paddr', 'filesize', 'memsize', 'align')
        dyn = Struct('Dyn', '<qQ', 'tag', 'val')
        rel = Struct('Rel', '<QQ', 'off', 'info')
        rela = Struct('Rela', '<QQQ', 'off', 'info', 'addend')
        sym = Struct('Sym', '<IBBHQQ', 'name_off', 'info', 'other', 'shndx', 'val', 'size')
        addr = struct.Struct('<Q')

    def __init__(self, fileobj=None):
        self.linked = False
        self.link_map = {}
        self.exports = {}
        self.ph = []
        self.sh = []

        self.path = None
        if isinstance(fileobj, str):
            self.path = fileobj
            fileobj = open(self.path, 'rb')
        f = self.f = fileobj

        codec = self.codec
        # ident
        ident = self.ident = codec.file_ident.read_from(f)
        assert(ident.magic == b'\x7fELF' and ident.elf_class == ELFCLASS64 and ident.elf_data == ELFDATA2LSB and ident.file_version == EV_CURRENT)

        # file header
        fh = self.fh = codec.file_header.read_from(f)

        # program headers
        if fh.phoff > 0 and fh.phnum > 0:
            phnum = fh.phnum

            if self.fh.phnum == 0xffff:
                first = codec.program_header.read_from(f, fh.phoff)
                phnum = first.info

            f.seek(fh.phoff)
            for i in range(phnum):
                ph = codec.program_header.read_from(f)
                self.ph.append(ph)

        # sections
        if fh.shoff > 0 and fh.shnum > 0:
            f.seek(fh.shoff)
            for i in range(fh.shnum):
                sh = codec.section_header.read_from(f)
                self.sh.append(sh)

        self.shstrtab = b''
        if 0 < fh.shstrndx < len(self.sh):
            sh = self.sh[fh.shstrndx]
            f.seek(sh.off)
            self.shstrtab = f.read(sh.size)

        # section names
        '''
        for sh in self.sh:
            name = self.shstrtab[sh.nameoff:].split(b'\0', 1)[0]
            print(name.decode('utf8').ljust(20), sh)
        '''

        # parse DYN
        self.dyn = []
        dynd = defaultdict(list)
        for ph in self.ph:
            if ph.type == PT.DYNAMIC:
                f.seek(ph.off)
                for i in range(ph.filesize // codec.dyn.size):
                    dyn = codec.dyn.read_from(f)
                    if dyn.tag == DT.NULL:
                        break
                    self.dyn.append(dyn)
                    try:
                        dynd[DT(dyn.tag)].append(dyn)
                    except ValueError:
                        pass

        # load strtab
        self.strtab = b''
        if DT.STRTAB in dynd and DT.STRSZ in dynd:
            f.seek(dynd[DT.STRTAB][0].val)
            self.strtab = f.read(dynd[DT.STRSZ][0].val)

        # load symtab
        self.symtab = []
        if DT.SYMTAB in dynd:
            gnuhash = dynd[DT.GNU_HASH]
            if gnuhash:
                addr = gnuhash[0].val
                for ph in self.ph:
                    if ph.vaddr <= addr and addr < ph.vaddr + ph.memsize:
                        off = addr - ph.vaddr
                        f.seek(ph.off + off)
                        data = f.read(ph.filesize - off)
                        base, count = ElfGnuHash.count(data, addr=codec.addr)
                        data = data[base:]

                        f.seek(dynd[DT.SYMTAB][0].val)
                        syment = dynd[DT.SYMENT][0].val
                        for i in range(count):
                            sym = codec.sym.read_from(f)
                            self.symtab.append(sym)
                        break

        # load relocations
        self.rel = []
        def load_rel(off, relsz, relent, *, rela=False):
            if all((off, relsz, relent)):
                off, relsz, relent = off[0].val, relsz[0].val, relent[0].val
                cls = codec.rela if rela else codec.rel
                count = min(relent, relsz // cls.size)
                f.seek(off)
                ret = []
                for i in range(count):
                    rel = cls.read_from(f)
                    ret.append(rel)
                return ret
            return []

        self.rel += load_rel(dynd[DT.REL], dynd[DT.RELSZ], dynd[DT.RELENT])
        self.rel += load_rel(dynd[DT.RELA], dynd[DT.RELASZ], dynd[DT.RELAENT], rela=True)
        pltrel_is_a = dynd[DT.PLTREL] and dynd[DT.PLTREL][0].val == DT.RELA
        self.rel += load_rel(dynd[DT.JMPREL], dynd[DT.PLTRELSZ], dynd[DT.RELAENT] if pltrel_is_a else dynd[DT.RELENT], rela=pltrel_is_a)

        # map and relocate library
        self.base = self.dlopen()

    def section_name(self, sh):
        name = self.shstrtab[sh.nameoff:].split(b'\0', 1)[0]
        return name.decode('utf8')

    def dlopen(self):
        ## map library
        loads = [ph for ph in self.ph if ph.type == PT.LOAD and ph.memsize > 0]

        # 1. map a huge contiguous allocation
        low_addr = min([ph.vaddr for ph in loads])
        high_addr = max([ph.vaddr + ph.memsize for ph in loads])
        size = align(high_addr - low_addr)
        base = mmap(low_addr, size, PROT_READ|PROT_WRITE)

        # 2. copy all the data in
        f = self.f
        for ph in loads:
            f.seek(ph.off)
            off = ph.vaddr-low_addr
            f.readinto(ffi.buffer(base + off, ph.filesize))

        # 3. link symbols
        for sym in self.symtab:
            name = self.strtab[sym.name_off:].split(b'\0', 1)[0].decode('utf8')

            # FIXME: x86_64 specific
            sym_bind = STB(sym.info >> 4)
            sym_type = STT(sym.info & 0xf)

            shndx = sym.shndx
            section_name = ''
            if sym.val and 0 < shndx < len(self.sh):
                sh = self.sh[shndx]
                section_name = self.section_name(sh)
                addr = base + sym.val
            else:
                addr = self.resolve(name)

            self.link_map[name] = addr
            print(f"{section_name:10} {name:30} {str(sym_bind):12} {str(sym_type):12} {str(STV(sym.other)):12} {addr}")
            # print(section_name.ljust(10), name.ljust(30), STB(sym_bind), STT(sym_type), STV(sym.other), addr, hex(sym.val))

        # 4. apply relocations
        for rel in self.rel:
            # FIXME: x86_64 specific
            rel_sym = rel.info >> 32
            rel_type = rel.info & 0xff
            if rel_type == R_AMD64.RELATIVE:
                pass
            elif rel_type == R_AMD64.JUMP_SLOT:
                pass
            else:
                raise Exception(f"unsupported relocation type: {rel_type}")
            # print(rel_sym, rel_type)

        # 5. mprotect each segment
        for ph in loads:
            off = ph.vaddr-low_addr
            end = align(off + ph.memsize)
            off &= ~(ALIGN-1)
            size = end - off
            prot = 0
            if ph.flags & PF.READ:  prot |= PROT_READ
            if ph.flags & PF.WRITE: prot |= PROT_WRITE
            if ph.flags & PF.EXEC:  prot |= PROT_EXEC
            mprotect(base + off, size, prot)

        self.linked = True
        return base

    def resolve(self, name):
        if name in self.link_map:
            return self.link_map[name]
        elif self.linked:
            raise NameError(name)

        if name == '__ctype_toupper_loc':
            toupper = ffi.new('char[]', 128 * 3)
            for i in range(256):
                try:
                    toupper[128 + i] = chr(i).upper()[0].encode('ascii')
                except UnicodeEncodeError:
                    pass
            for i in range(128):
                toupper[i] = toupper[i + 256]
            return toupper

        # linux->macos name map
        name_map = {
            # FIXME: stdio mapping won't be portable if they try to actually access members of FILE *
            # but it will be fine if they're just passing it into fprintf() functions
            'stdin': '__stdinp',
            'stdout': '__stdoutp',
            'stderr': '__stderrp',

            '__vfprintf_chk': 'vfprintf',
            '__vsnprintf_chk': 'vsnprintf',
        }
        if name in name_map:
            name = name_map[name]
        addr = _libc_dlsym(name)
        return addr

    def cffi_dlopen(self, ffi):
        lib = CrossElfLib(self)
        for name, decl in ffi._parser._declarations.items():
            if name.startswith('function '):
                name = name.split(' ', 1)[1]
                sig = decl[0].c_name_with_marker.replace('&', '', 1)
                if name in self.link_map:
                    setattr(lib, name, ffi.cast(sig, self.link_map[name]))
                else:
                    raise NameError(name)
        return lib

def dlopen(path, flags=0):
    return CrossElf64(path)

def cffi_dlopen(ffi, path, flags=0):
    return CrossElf64(path).cffi_dlopen(ffi)

# addr = mmap(None, 0x1000, PROT_ALL)

# elf = dlopen('/Users/aegis/build/cheetah/lib/linux/x86_64/libpv_cheetah.so')
# pv_sample_rate = ffi.cast('int (*)()', elf.resolve('pv_sample_rate'))
# pv_cheetah_frame_length = ffi.cast('int (*)()', elf.resolve('pv_cheetah_frame_length'))
# print(pv_sample_rate(), pv_cheetah_frame_length())


ffi2 = FFI()
ffi2.cdef(r'''
int pv_sample_rate();
''')
lib2 = cffi_dlopen(ffi2, '/Users/aegis/build/cheetah/lib/linux/x86_64/libpv_cheetah.so')
print(lib2.pv_sample_rate())
