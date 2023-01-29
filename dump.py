# File by Jonas Pöhler https://github.com/poehlerj/linux_coredump
#
# Note:
# based on work from https://github.com/Angelomirabella/linux_coredump/blob/master/coredump.py
# (no license statement)
# based on work from https://github.com/checkpoint-restore/criu/tree/criu-dev/coredump
# (GPL licensed)
#
# The code from criu-dev has now been replaced by functionality from elffile.py
# There should by no criu code in here any more
# TODO: Check if there is Angelomirabella code in here and what its lisence status is

import mmap
import sys
import collections
import struct
import logging

#sys.path.append("/root/vol/linux_coredump/")
#import elffile
from . import elffile #as elffile

from volatility3.framework.objects import StructType

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, format="%(levelname)-8s [%(filename)s:%(lineno)d] %(message)s")
logger = logging.getLogger("elffile")

#% see https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/ptrace.h for pt_regs structure definition
pt_regs_x86_32 = [
        'ebx',
        'ecx',
        'edx',
        'esi',
        'edi',
        'ebp',
        'eax',
        'ds',
        'es',
        'fs',
        'gs',
        'orig_eax',
        'eip',
        'cs',
        'eflags',
        'esp',
        'ss'
    ]
pt_regs_x86_64 = [
        'r15',
        'r14',
        'r13',
        'r12',
        'rbp',
        'rbx',
        'r11',
        'r10',
        'r9',
        'r8',
        'rax',
        'rcx',
        'rdx',
        'rsi',
        'rdi',
        'orig_ax',
        'rip',
        'cs',
        'eflags',
        'rsp',
        'ss'
    ]



class coredump:
    """
    This class creates a elf core dump file using elffile,
    based on volatility3 data structures of a Linux system
    (task struct and its siblings)
    and writes them to a (sparse) file
    """
    # Flags for vm areas in mm struct
    VM_READ = 0x0001  # /* currently active flags */
    VM_WRITE = 0x0002
    VM_EXEC = 0x0004
    VM_SHARED = 0x0008

    # Supported architectures (32bit x86 not really tested, working on 64bit x86_64)
    ELF_ISA_x86 = 3
    ELF_ISA_x86_64 = 0x3E

    def __init__(self, context, task: StructType, kernel, isa=ELF_ISA_x86_64):
        self.context = context
        self.task = task
        self.vma_list = task.mm.get_mmap_iter()

        self.kernel_layer = context.modules[kernel].layer_name

        self.threads_registers = {task.pid: self._parse_kernel_stack(task)}

        # Get registers from all additional threads
        for t in task.thread_group:
            regs = self._parse_kernel_stack(t)
            if regs:
                self.threads_registers[t.pid] = regs

        self.isa = isa


    def _parse_kernel_stack(self, task):
        result = collections.OrderedDict()
        # vmlinux = self.context.modules[self.config['kernel']]

        # proc_as = task.get_process_address_space()
        if hasattr(task, "stack"):
            # According to Linux kernel sousces (https://elixir.bootlin.com/linux/v5.8/source/arch/x86/include/asm/processor.h#L843)
            # pt_regs can be found on the stack at task->stack + THREAD_SIZE  - TOP_OF_KERNEL_STACPADDING - sizeof(pointer)
            # THREAD_SIZE is (PAGE_SIZE << THREAD_SIZE_ORDER), with THREAD_SIZE_ORDER being (2+KASAN_STACK_ORDER)
            # KASAN_STACK_ORDER IS 0 (w/o KASAN) or 1 (w/ KASAN)
            # So this value is valid here systems without KASAN only
            # TOP_OF_KERNEL_STACKPADDING is 0 for 64bit (it is 8 or 16 for x86_32 without/with CONFIG_VM86))
            addr = task.stack + (1 << 14)

            for reg in pt_regs_x86_64[::-1]:  # reverse list, because we read up in the stack
                # debug.info("Reading {:016x}".format(addr))
                # 64-bit only
                addr -= 0x8
                val_raw = self.context.layers.read(self.kernel_layer, addr, 0x8)
                val = struct.unpack('<Q', val_raw)[0]
                result[reg] = val
            return result
        return None


    """
    Function to convert memory access bits from vma area (task struct -> mm) into
    ELF section header flags
    """

    def get_shf_from_vmas(self, vma_flags):
        flags = elffile.SHF.SHF_ALLOC
        if vma_flags & self.VM_WRITE:
            flags |= elffile.SHF.SHF_WRITE
        if vma_flags & self.VM_EXEC:
            flags |= elffile.SHF.SHF_EXECINSTR
        return flags

    """
    Function to convert memory access bits from vma area (task struct -> mm) into
    ELF program header flags
    """

    def get_phf_from_vmas(self, vma_flags):
        flags = 0
        if vma_flags & self.VM_READ:
            flags = flags | elffile.PF.PF_R
        if vma_flags & self.VM_WRITE:
            flags = flags | elffile.PF.PF_W
        if vma_flags & self.VM_EXEC:
            flags = flags | elffile.PF.PF_X
        return flags

    def read_addr_range(self, task, start, end):
        PAGESIZE = 4096

        # set the as with our new dtb so we can read from userland
        proc_layer_name = task.add_process_layer()
        if not proc_layer_name:
            return

        proc_layer = self.context.layers[proc_layer_name]

        while start < end:
            yield proc_layer.read(start, PAGESIZE, pad=True)
            start = start + PAGESIZE

    def ffs(self, x):
        """ Calculate the index (starting at LSB) of the first set bit in x
            ffs(0) will return -1
        """
        return (x & -x).bit_length() - 1

    def gen_prpsinfo(self):
        """
        Generate NT_PRPSINFO note for process pid.
        """
        prpsinfo = elffile.ElfNotePRPSINFO()

        # hr: The old translation from task struct process status to elf core status
        # did not make much sense. se also:
        # https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L84
        # https://elixir.bootlin.com/linux/latest/source/tools/perf/builtin-sched.c#L110
        # Linux kernel code actually does this: i = state ? ffz(~state) + 1 : 0;
        # so let's use the same approach here. (ffz(~z) is the same as ffs(z)
        prpsinfo.pr_state = (self.ffs(self.task.state) if self.task.state > 0 else 0)

        """"
        R: Running
        S: Sleeping
        D: Waiting on I/O (Uninterruptible sleep)
        T: Traced or stopped
        Z: Zombie (terminated but not yet cleaned up by its parent)
        W: Paging (only in Linux 2.6.18 and later)
        """
        prpsinfo.pr_sname = ('.' if prpsinfo.pr_state > 5 else "RSDTZW"[prpsinfo.pr_state]).encode("utf-8")
        prpsinfo.pr_zomb = 1 if prpsinfo.pr_state == 4 else 0
        prpsinfo.pr_nice = 0  # default
        prpsinfo.pr_flag = 0  # default
        prpsinfo.pr_uid = self.task.cred.uid.val
        prpsinfo.pr_gid = self.task.cred.gid.val
        prpsinfo.pr_pid = self.task.pid
        prpsinfo.pr_ppid = self.task.parent.pid
        prpsinfo.pr_pgrp = self.task.parent.cred.gid.val
        prpsinfo.pr_sid = 0  # default
        prpsinfo.pr_fname = b''.join(map(lambda x: int(x).to_bytes(1, byteorder='big'), self.task.comm))

        size_to_read = self.task.mm.arg_end - self.task.mm.arg_start
        proc_layer = self.context.layers[self.task.add_process_layer()]
        args: bytes = proc_layer.read(self.task.mm.arg_start, size_to_read, pad=True)
        prpsinfo.pr_psargs = (" ".join(map(lambda x: x.decode('utf-8'), args.split(b'\x00')))).strip().encode("utf-8")

        return prpsinfo

    def gen_prstatus(self, thread):
        """
        Generate NT_PRSTATUS note for thread tid of process pid.
        """
        regs = self.threads_registers[thread.pid]
        logger.debug("Registers for PID %d: %s", thread.pid, regs)

        prstatus = elffile.ElfNotePRSTATUS()
        prstatus.pid = thread.pid
        prstatus.ppid = thread.parent.pid
        prstatus.pgrp = thread.parent.cred.gid.val
        prstatus.sid = 0  # default
        prstatus.registers.registers = regs
        regs["fs_base"] = thread.thread.fsbase
        return prstatus


    # def gen_siginfo(self):
    ## NT_SIGINFO not implemented so far


    def gen_thread_notes(self, thread):
        notes = []

        prstatus = self.gen_prstatus(thread)
        print("Notes: appending ", prstatus, prstatus.registers)
        notes.append(prstatus)
        # notes.append(self.gen_fpregset(pid, tid))  floating point register should be in task->fpu
        # notes.append(self.gen_x86_xstate(pid, tid)) unknown
        # notes.append(self.gen_siginfo())
        return notes

    """
    def _gen_files(self):
        ""
        Generate NT_FILE note for process pid.
        ""

        class mmaped_file_info:
            start = None
            end = None
            file_ofs = None
            name = None

        infos = []
        for vma in self.task.mm.get_mmap_iter():
            fname = vma.vm_file
            if fname == 0:
                continue

            dentry = vma.vm_file.f_path.dentry
            fname = ""
            while dentry:
                name = dentry.d_name.name_as_str()
                if name != "/":
                    fname = "/" + name + fname

                if dentry == dentry.d_parent:
                    dentry = None
                else:
                    dentry = dentry.d_parent

            off = vma.vm_pgoff

            info = mmaped_file_info()
            info.start = vma.vm_start
            info.end = vma.vm_end
            info.file_ofs = off
            ##info.name = ("xx"+fname).encode("utf-8")
            ##info.name = fname.encode("utf-8")
            info.name = "xx".encode("utf-8")

            infos.append(info)

        # /*
        #  * Format of NT_FILE note:
        #  *
        #  * long count     -- how many files are mapped
        #  * long page_size -- units for file_ofs
        #  * array of [COUNT] elements of
        #  *   long start
        #  *   long end
        #  *   long file_ofs
        #  * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
        #  */
        fields = []
        fields.append(("count", ctypes.c_long))
        fields.append(("page_size", ctypes.c_long))
        for i in range(len(infos)):
            fields.append(("start" + str(i), ctypes.c_long))
            fields.append(("end" + str(i), ctypes.c_long))
            fields.append(("file_ofs" + str(i), ctypes.c_long))
        for i in range(len(infos)):
            fields.append(("name" + str(i), ctypes.c_char * (len(infos[i].name) + 1)))

        class elf_files(ctypes.Structure):
            _fields_ = fields

        data = elf_files()
        data.count = len(infos)
        data.page_size = PAGESIZE
        for i in range(len(infos)):
            info = infos[i]
            setattr(data, "start" + str(i), info.start)
            setattr(data, "end" + str(i), info.end)
            setattr(data, "file_ofs" + str(i), info.file_ofs)
            setattr(data, "name" + str(i), info.name)

        nhdr = elf.Elf64_Nhdr()
        nhdr.n_namesz = 5  # XXX strlen + 1
        nhdr.n_descsz = ctypes.sizeof(elf_files())
        nhdr.n_type = elf.NT_FILE

        note = elf_note()
        note.nhdr = nhdr
        note.owner = "CORE"
        note.data = data

        return note
    """

    """
    def _gen_files_x86(self):
        ""
        Generate NT_FILE note for process pid.
        ""

        class mmaped_file_info:
            start = None
            end = None
            file_ofs = None
            name = None

        infos = []
        for vma in self.vma_list:
            (fname, major, minor, ino, pgoff) = vma.info(self.task)
            if fname.startswith('/') == False:
                continue

            off = pgoff
            info = mmaped_file_info()
            info.start = vma.vm_start
            info.end = vma.vm_end
            info.file_ofs = off
            info.name = fname

            infos.append(info)

        fields = []
        fields.append(("count", ctypes.c_uint32))
        fields.append(("page_size", ctypes.c_uint32))
        for i in range(len(infos)):
            fields.append(("start" + str(i), ctypes.c_uint32))
            fields.append(("end" + str(i), ctypes.c_uint32))
            fields.append(("file_ofs" + str(i), ctypes.c_uint32))
        for i in range(len(infos)):
            fields.append(("name" + str(i), ctypes.c_char * (len(infos[i].name) + 1)))

        class elf_files(ctypes.Structure):
            _fields_ = fields

        data = elf_files()
        data.count = len(infos)
        data.page_size = PAGESIZE
        for i in range(len(infos)):
            info = infos[i]
            setattr(data, "start" + str(i), info.start)
            setattr(data, "end" + str(i), info.end)
            setattr(data, "file_ofs" + str(i), info.file_ofs)
            setattr(data, "name" + str(i), info.name)

        nhdr = elf.Elf32_Nhdr()
        nhdr.n_namesz = 5  # XXX strlen + 1
        nhdr.n_descsz = ctypes.sizeof(elf_files())
        nhdr.n_type = elf.NT_FILE

        note = elf_note()
        note.nhdr = nhdr
        note.owner = "CORE"
        note.data = data

        return note
    """

    def gen_notes(self):
        """
        Generate notes for core dump of process pid.
        """
        notes = elffile.ElfNotes()

        # Generate PRPSINFO note from task struct information in self.task
        notes.append(self.gen_prpsinfo())

        # Generate PRSTATUS notes for thread first
        # (could be multiple notes: regs, fpregs, signals, etc. For now, only regs are generated)
        notes.append(self.gen_thread_notes(self.task))

        # Geerate PRSTATUS notes for all other threads
        for thread in self.task.thread_group:
            if thread.pid == self.task.pid:
                continue

            notes.append(self.gen_thread_notes(thread))

        # Append AUXV notes (needed by jmap for entry point)
        notes.append(elffile.ElfNoteAUXV(self.task.mm.saved_auxv))

        # notes.append(self._gen_files())
        logger.debug("Notes are %s", str(notes))
        return notes

    # Create ElfFileIdent: The very first part of the header
    # defines ABI (Linux), 64 bit, Little Endian


    def makeEFI(self):
        efi = elffile.ElfFileIdent()
        efi.magic = b'\x7fELF'
        efi.elfClass = elffile.ElfClass.ELFCLASS64
        if self.isa == self.ELF_ISA_x86:
            efi.elfClass = elffile.ElfClass.ELFCLASS32
        efi.fileVersion = elffile.EV.EV_CURRENT
        efi.osabi = elffile.ElfOsabi.ELFOSABI_LINUX
        efi.abiversion = 0
        efi.elfData = elffile.ElfData.ELFDATA2LSB
        return efi


    # Create ElfSectionHeader
    def makeSH(self, name=b'', type=elffile.SHT.SHT_NULL, addr=0, offset=0, size=0, entsize=0, flags=0, link=0, info=0,
               align=1):
        # create one section header
        sh = self.ef.sectionHeaderClass()
        sh.content = b'\0' * size
        sh.section_size = size
        sh.name = name
        sh.offset = offset
        sh.type = type
        sh.addr = addr
        sh.flags = flags
        sh.entsize = entsize
        sh.info = info
        sh.link = link
        sh.addralign = align
        return sh


    def makePH(self, type=elffile.PT.PT_NULL, offset=None, vaddr=None, paddr=None, filesz=None, memsz=None, flags=None,
               align=None):
        ph = self.ef.programHeaderClass()
        ph.content = b'\0' * filesz
        ph.type = type
        ph.offset = offset
        ph.vaddr = vaddr
        ph.paddr = paddr
        ph.filesz = filesz
        ph.memsz = memsz
        ph.flags = flags
        ph.align = align
        return ph


    def makePHbySH(self, sh, type=elffile.PT.PT_NULL, vaddr=None, paddr=None, flags=0):
        ph = self.ef.programHeaderClass()
        ph.content = sh.content
        ph.type = type
        ph.offset = sh.offset
        ph.vaddr = vaddr
        ph.paddr = paddr
        ph.filesz = sh.section_size
        ph.memsz = sh.section_size
        ph.flags = flags
        ph.align = sh.addralign
        sh._ph = ph
        return ph


    class DataGenerator:
        def __init__(self, coredump, task, start, end) -> None:
            super().__init__()
            self.coredump = coredump
            self.task = task
            self.start = start
            self.end = end

        def generate(self):
            for page in self.coredump.read_addr_range(self.task, self.start, self.end):
                yield page

        def __len__(self):
            return self.end - self.start


    def checkAllZero(self, gen):
        for block in gen.generate():
            if block == b'\0' * len(block):
                continue
            return False
        return True


    def generate_coredump(self):
        """
        Generate core dump for pid.
        """
        efi = self.makeEFI()  #
        ef = elffile.ElfFile.encodedClass(efi)("<xyz>", efi)
        self.ef = ef

        # Add ElfFileHeader
        efh = ef.fileHeaderClass()
        efh.type = elffile.ET.ET_CORE
        efh.machine = elffile.EM.EM_X86_64
        if self.isa == self.ELF_ISA_x86:
            efh.machine = elffile.EM.EM_386
        efh.version = 1
        efh.entry = 0
        efh.programHeaderClass = ef.programHeaderClass()
        efh.sectionHeaderClass = ef.sectionHeaderClass()
        efh.shstrndx = 0

        efh.ehsize = efh.size + efi.size
        efh.shentsize = efh.sectionHeaderClass.size
        efh.phentsize = efh.programHeaderClass.size
        ef.fileHeader = efh

        # just for now. This may have to be removed as soon as this empty null header is created automatically/implicitely
        sheader = self.makeSH(name=b'', type=elffile.SHT.SHT_NULL, addr=0, offset=0,
                              size=0, entsize=0, flags=0, link=0, info=0, align=0)
        ef.sectionHeaders.append(sheader)

        enotes = self.gen_notes()
        block = bytearray(enotes.size)
        enotes.pack_into(block)
        sheader = self.makeSH(name=b"note0", type=elffile.SHT.SHT_NOTE, addr=0x1234, offset=0x1234,
                              size=len(block), entsize=0, flags=elffile.SHF.SHF_ALLOC, link=0, info=0, align=1)
        sheader.content = block
        ef.sectionHeaders.append(sheader)
        pheader = self.makePHbySH(sheader, type=elffile.PT.PT_NOTE, vaddr=0, paddr=0,
                                  flags=elffile.PF.PF_X | elffile.PF.PF_R | elffile.PF.PF_W)
        ef.programHeaders.append(pheader)

        # new version
        for vma in self.vma_list:
            size = vma.vm_end - vma.vm_start
            sheader = self.makeSH(name=b'load', type=elffile.SHT.SHT_PROGBITS)
            sheader.content = self.DataGenerator(self, self.task, vma.vm_start, vma.vm_end)
            if self.checkAllZero(sheader.content):
                continue
            print("adding ", size, "at", vma.vm_start)
            sheader.section_size = size
            sheader.addr = vma.vm_start
            sheader.flags = self.get_shf_from_vmas(vma.vm_flags)
            ## TODO: ADD RIGHT DETAILS after memsz....
            pheader = self.makePH(filesz=size, memsz=size, flags=self.get_phf_from_vmas(vma.vm_flags), vaddr=vma.vm_start,
                                  paddr=0, align=1, type=elffile.PT.PT_LOAD)
            sheader._ph = pheader
            # start = vma.vm_start ??? => is this vaddr? paddr? ??

            ef.sectionHeaders.append(sheader)
            ef.programHeaders.append(pheader)

        return ef


    def write(self, f):
        """
        Write core dump to file f.
        """
        sz = self.ef.size
        print("size is ", sz)
        f.seek(sz - 1)
        f.write(b'\0')
        f.flush()
        mm = mmap.mmap(f.fileno(), sz)
        self.ef.pack_into(mm)
        mm.close()
        f.close()
