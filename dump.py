# Functions and classes for creating core dump.
# Code is inspired by criucoredump [1].
#
# [1] https://github.com/checkpoint-restore/criu/tree/criu-dev/coredump

#
import io
import sys
from typing import List

from . import elf
from .elf import PF_R, VM_WRITE, VM_EXEC
import ctypes

from volatility3.framework.objects import StructType
from volatility3.framework.symbols.linux.extensions import vm_area_struct

PAGESIZE = 4096


class elf_note:
    nhdr = None  # Elf_Nhdr;
    owner = None  # i.e. CORE or LINUX;
    data = None  # Ctypes structure with note data;


class coredump:
    """
    A class to keep elf core dump components inside and
    functions to properly write them to file.
    """
    ehdr = None  # Elf ehdr;
    phdrs = []  # Array of Phdrs;
    notes = []  # Array of elf_notes;
    vmas = []  # Array of BytesIO with memory content;
    shdrs = []  # Array of Shdrs

    def __init__(self, context, task: StructType, vma_list: List[vm_area_struct], threads_registers, x86=False):
        self.context = context
        self.task = task
        self.vma_list = vma_list
        self.threads_registers = threads_registers
        self.x86 = x86

    def get_vma_flags(self, vma_flags):
        flags = 0
        # if vma_flags & VM_READ == VM_READ:
        flags = flags | elf.PF_R
        if vma_flags & VM_WRITE == VM_WRITE:
            flags = flags | elf.PF_W
        if vma_flags & VM_EXEC == VM_EXEC:
            flags = flags | elf.PF_X

        return flags

    def get_shdr_flags(self, vma_flags):
        flags = 0
        if vma_flags & elf.PF_X == elf.PF_X:
            flags = flags | elf.SHF_EXECINSTR
        flags = flags | elf.SHF_ALLOC
        if vma_flags & elf.PF_W == elf.PF_W:
            flags = flags | elf.SHF_WRITE

        return flags

    def read_addr_range(self, task, start, end):
        pagesize = 4096

        # set the as with our new dtb so we can read from userland
        proc_layer_name = task.add_process_layer()
        if not proc_layer_name:
            return

        proc_layer = self.context.layers[proc_layer_name]

        while start < end:
            yield proc_layer.read(start, pagesize, pad=True)
            start = start + pagesize

    def gen_vmas(self, ):

        class vma_class:
            data = None
            filesz = None
            memsz = None
            flags = None
            start = None

        vmas_tmp = []
        for vma in self.vma_list:
            size = vma.vm_end - vma.vm_start
            v = vma_class()
            v.filesz = size

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

            v.data = DataGenerator(self, self.task, vma.vm_start, vma.vm_end)

            v.memsz = size
            v.start = vma.vm_start
            v.flags = self.get_vma_flags(vma.vm_flags)
            vmas_tmp.append(v)
        return vmas_tmp

    def gen_prpsinfo(self):
        """
        Generate NT_PRPSINFO note for process pid.
        """

        if self.x86 is True:
            prpsinfo = elf.elf_prpsinfo32()
        else:
            prpsinfo = elf.elf_prpsinfo()

        ctypes.memset(ctypes.addressof(prpsinfo), 0, ctypes.sizeof(prpsinfo))

        TASK_ALIVE = 0x1
        TASK_DEAD = 0x2
        TASK_STOPPED = 0x3

        if self.task.state == TASK_ALIVE:
            prpsinfo.pr_state = 0
        elif self.task.state == TASK_DEAD:
            prpsinfo.pr_state = 4
        elif self.task.state == TASK_STOPPED:
            prpsinfo.pr_state = 3

        prpsinfo.pr_sname = '.'.encode("utf-8") if prpsinfo.pr_state > 5 else (
            "RSDTZW"[prpsinfo.pr_state].encode("utf-8"))
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

        if self.x86 is True:
            nhdr = elf.Elf32_Nhdr()
            nhdr.n_namesz = 5
            nhdr.n_descsz = ctypes.sizeof(elf.elf_prpsinfo32())
            nhdr.n_type = elf.NT_PRPSINFO

        else:
            nhdr = elf.Elf64_Nhdr()
            nhdr.n_namesz = 5
            nhdr.n_descsz = ctypes.sizeof(elf.elf_prpsinfo())
            nhdr.n_type = elf.NT_PRPSINFO

        note = elf_note()
        note.data = prpsinfo
        note.owner = "CORE"
        note.nhdr = nhdr

        return note

    def gen_prstatus(self, thread):
        """
        Generate NT_PRSTATUS note for thread tid of process pid.
        """
        regs = self.threads_registers[thread.pid]

        prstatus = elf.elf_prstatus()

        ctypes.memset(ctypes.addressof(prstatus), 0, ctypes.sizeof(prstatus))

        prstatus.pr_pid = thread.pid
        prstatus.pr_ppid = thread.parent.pid
        prstatus.pr_pgrp = thread.parent.cred.gid.val
        prstatus.pr_sid = 0  # default

        prstatus.pr_reg.r15 = regs["r15"]
        prstatus.pr_reg.r14 = regs["r14"]
        prstatus.pr_reg.r13 = regs["r13"]
        prstatus.pr_reg.r12 = regs["r12"]
        prstatus.pr_reg.rbp = regs["rbp"]
        prstatus.pr_reg.rbx = regs["rbx"]
        prstatus.pr_reg.r11 = regs["r11"]
        prstatus.pr_reg.r10 = regs["r10"]
        prstatus.pr_reg.r9 = regs["r9"]
        prstatus.pr_reg.r8 = regs["r8"]
        prstatus.pr_reg.rax = regs["rax"]
        prstatus.pr_reg.rcx = regs["rcx"]
        prstatus.pr_reg.rdx = regs["rdx"]
        prstatus.pr_reg.rsi = regs["rsi"]
        prstatus.pr_reg.rdi = regs["rdi"]
        prstatus.pr_reg.orig_rax = regs["orig_ax"]
        prstatus.pr_reg.rip = regs["rip"]
        prstatus.pr_reg.cs = regs["cs"]
        prstatus.pr_reg.eflags = regs["eflags"]
        prstatus.pr_reg.rsp = regs["rsp"]
        prstatus.pr_reg.ss = regs["ss"]
        prstatus.pr_reg.fs_base	= thread.thread.fsbase
        #	prstatus.pr_reg.gs_base		= regs["gs_base"]
        #	prstatus.pr_reg.ds		= regs["ds"]		MISSING
        #	prstatus.pr_reg.es		= regs["es"]
        #	prstatus.pr_reg.fs		= regs["fs"]
        #	prstatus.pr_reg.gs		= regs["gs"]

        nhdr = elf.Elf64_Nhdr()
        nhdr.n_namesz = 5
        nhdr.n_descsz = ctypes.sizeof(elf.elf_prstatus())
        nhdr.n_type = elf.NT_PRSTATUS

        note = elf_note()
        note.data = prstatus
        note.owner = "CORE"
        note.nhdr = nhdr

        return note

    def gen_prstatus_x86(self, thread):
        """
        Generate NT_PRSTATUS note for thread tid of process pid.
        """
        regs = self.threads_registers[str(thread.pid)]

        prstatus = elf.elf_prstatus32()

        ctypes.memset(ctypes.addressof(prstatus), 0, ctypes.sizeof(prstatus))

        prstatus.pr_pid = thread.pid
        prstatus.pr_ppid = thread.parent.pid
        prstatus.pr_pgrp = thread.parent.gid
        prstatus.pr_sid = 0  # default

        if "ebx" in regs:
            prstatus.pr_reg.ebx = regs["ebx"]
            prstatus.pr_reg.ecx = regs["ecx"]
            prstatus.pr_reg.edx = regs["edx"]
            prstatus.pr_reg.esi = regs["esi"]
            prstatus.pr_reg.edi = regs["edi"]
            prstatus.pr_reg.ebp = regs["ebp"]
            prstatus.pr_reg.eax = regs["eax"]
            prstatus.pr_reg.ds = regs["ds"]
            prstatus.pr_reg.es = regs["es"]
            prstatus.pr_reg.fs = regs["fs"]
            prstatus.pr_reg.gs = regs["gs"]
            prstatus.pr_reg.orig_eax = regs["orig_eax"]
            prstatus.pr_reg.eip = regs["eip"]
            prstatus.pr_reg.cs = regs["cs"]
            prstatus.pr_reg.eflags = regs["eflags"]
            prstatus.pr_reg.esp = regs["esp"]
            prstatus.pr_reg.ss = regs["ss"]
        else:
            prstatus.pr_reg.ebx = regs["rbx"]
            prstatus.pr_reg.ecx = regs["rcx"]
            prstatus.pr_reg.edx = regs["rdx"]
            prstatus.pr_reg.esi = regs["rsi"]
            prstatus.pr_reg.edi = regs["rdi"]
            prstatus.pr_reg.ebp = regs["rbp"]
            prstatus.pr_reg.eax = regs["rax"]
            # prstatus.pr_reg.ds	= regs["ds"]
            # prstatus.pr_reg.es	= regs["es"]
            # prstatus.pr_reg.fs	= regs["fs"]
            # prstatus.pr_reg.gs	= regs["gs"]
            # prstatus.pr_reg.orig_eax	= regs["orig_eax"]
            prstatus.pr_reg.eip = regs["rip"]
            prstatus.pr_reg.cs = regs["cs"]
            prstatus.pr_reg.eflags = regs["eflags"]
            prstatus.pr_reg.esp = regs["rsp"]
            prstatus.pr_reg.ss = regs["ss"]

        nhdr = elf.Elf32_Nhdr()
        nhdr.n_namesz = 5
        nhdr.n_descsz = ctypes.sizeof(elf.elf_prstatus32())
        nhdr.n_type = elf.NT_PRSTATUS

        note = elf_note()
        note.data = prstatus

        note.owner = "CORE"
        note.nhdr = nhdr

        return note

    def gen_siginfo(self):
        """
        Generate NT_SIGINFO note for thread tid of process pid.
        """
        siginfo = elf.siginfo_t()
        # FIXME zeroify everything for now
        ctypes.memset(ctypes.addressof(siginfo), 0, ctypes.sizeof(siginfo))

        nhdr = elf.Elf64_Nhdr()
        nhdr.n_namesz = 5
        nhdr.n_descsz = ctypes.sizeof(elf.siginfo_t())
        nhdr.n_type = elf.NT_SIGINFO

        note = elf_note()
        note.data = siginfo
        note.owner = "CORE"
        note.nhdr = nhdr

        return note

    def gen_thread_notes(self, thread):
        notes = []

        notes.append(self.gen_prstatus(thread))
        #	notes.append(self.gen_fpregset(pid, tid))  floating point register do not know hot to get them
        #	notes.append(self.gen_x86_xstate(pid, tid)) unknown
        # notes.append(self.gen_siginfo())

        return notes

    def gen_thread_notes_x86(self, thread):
        notes = []

        notes.append(self.gen_prstatus_x86(thread))

        return notes

    def _gen_files(self):
        """
        Generate NT_FILE note for process pid.
        """

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
            info.name = fname.encode("utf-8")

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

    def _gen_files_x86(self):
        """
        Generate NT_FILE note for process pid.
        """

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

    def _gen_auxv(self):
        auxv = self.task.mm.saved_auxv
        auxv_arr = (elf.Elf64_auxv_t * int(len(auxv) / 2))()

        index = 0
        while index + 1 < len(auxv_arr):
            aux = elf.Elf64_auxv_t()
            aux.a_type = auxv[index * 2]
            aux.a_un.a_val = auxv[index * 2 + 1]
            auxv_arr[index] = aux
            index += 1

        nhdr = elf.Elf64_Nhdr()
        nhdr.n_namesz = 5  # XXX strlen + 1
        nhdr.n_descsz = ctypes.sizeof(auxv_arr)
        nhdr.n_type = elf.NT_AUXV

        note = elf_note()
        note.nhdr = nhdr
        note.owner = "CORE"
        note.data = auxv_arr

        return note

    def gen_notes(self):
        """
        Generate notes for core dump of process pid.
        """
        notes = []
        notes.append(self.gen_prpsinfo())

        # Main thread first
        notes += self.gen_thread_notes(self.task)

        # Then other threads
        for t in self.task.thread_group:
            if t.pid == self.task.pid:
                continue

            notes += self.gen_thread_notes(t)

        notes.append(self._gen_auxv())
        notes.append(self._gen_files())
        return notes

    def gen_notes_x86(self):
        """
        Generate notes for core dump of process pid.
        """
        notes = []
        notes.append(self.gen_prpsinfo())

        threads = self.task.threads()

        # Main thread first
        notes += self.gen_thread_notes_x86(self.task)

        # Then other threads
        for t in threads:
            if t.pid == self.task.pid:
                continue

            notes += self.gen_thread_notes_x86(t)

        notes.append(self._gen_files_x86())
        return notes

    def gen_phdrs(self, notes, vmas):
        """
        Generate program headers for process pid.
        """
        phdrs = []

        if self.x86 is True:
            offset = ctypes.sizeof(elf.Elf32_Ehdr())
            offset += (len(vmas) + 1) * ctypes.sizeof(elf.Elf32_Phdr())
            phdr = elf.Elf32_Phdr()

        else:
            offset = ctypes.sizeof(elf.Elf64_Ehdr())
            offset += (len(vmas) + 1) * ctypes.sizeof(elf.Elf64_Phdr())
            phdr = elf.Elf64_Phdr()

        filesz = 0

        for note in notes:
            filesz += ctypes.sizeof(note.nhdr) + ctypes.sizeof(note.data) + 8

        # PT_NOTE

        ctypes.memset(ctypes.addressof(phdr), 0, ctypes.sizeof(phdr))
        phdr.p_type = elf.PT_NOTE
        phdr.p_offset = offset
        phdr.p_filesz = filesz
        phdr.p_flags = PF_R  # Read

        phdrs.append(phdr)

        note_align = PAGESIZE - ((offset + filesz) % PAGESIZE)

        if note_align == PAGESIZE:
            note_align = 0

        offset += note_align

        # VMA phdrs

        for vma in self.vmas:
            offset += filesz
            filesz = vma.filesz

            if self.x86 is True:
                phdr = elf.Elf32_Phdr()
            else:
                phdr = elf.Elf64_Phdr()

            ctypes.memset(ctypes.addressof(phdr), 0, ctypes.sizeof(phdr))
            phdr.p_type = elf.PT_LOAD
            phdr.p_align = 1
            phdr.p_paddr = 0
            phdr.p_offset = offset
            phdr.p_vaddr = vma.start
            phdr.p_memsz = vma.memsz
            phdr.p_filesz = vma.filesz
            phdr.p_flags = vma.flags

            phdrs.append(phdr)

        return phdrs

    def gen_ehdr(self, phdrs):
        """
        Generate elf header for process pid with program headers phdrs.
        """
        ehdr = elf.Elf64_Ehdr()

        ctypes.memset(ctypes.addressof(ehdr), 0, ctypes.sizeof(ehdr))
        ehdr.e_ident[elf.EI_MAG0] = elf.ELFMAG0
        ehdr.e_ident[elf.EI_MAG1] = elf.ELFMAG1
        ehdr.e_ident[elf.EI_MAG2] = elf.ELFMAG2
        ehdr.e_ident[elf.EI_MAG3] = elf.ELFMAG3
        ehdr.e_ident[elf.EI_CLASS] = elf.ELFCLASS64
        ehdr.e_ident[elf.EI_DATA] = elf.ELFDATA2LSB
        ehdr.e_ident[elf.EI_VERSION] = elf.EV_CURRENT

        ehdr.e_type = elf.ET_CORE
        ehdr.e_machine = elf.EM_X86_64
        ehdr.e_version = elf.EV_CURRENT
        ehdr.e_phoff = ctypes.sizeof(elf.Elf64_Ehdr())
        ehdr.e_ehsize = ctypes.sizeof(elf.Elf64_Ehdr())
        ehdr.e_phentsize = ctypes.sizeof(elf.Elf64_Phdr())
        # FIXME Case len(phdrs) > PN_XNUM should be handled properly.
        # See fs/binfmt_elf.c from linux kernel.
        ehdr.e_phnum = len(phdrs)

        return ehdr

    def gen_ehdr_x86(self, phdrs):
        """
        Generate elf header for process pid with program headers phdrs.
        """
        ehdr = elf.Elf32_Ehdr()

        ctypes.memset(ctypes.addressof(ehdr), 0, ctypes.sizeof(ehdr))
        ehdr.e_ident[elf.EI_MAG0] = elf.ELFMAG0
        ehdr.e_ident[elf.EI_MAG1] = elf.ELFMAG1
        ehdr.e_ident[elf.EI_MAG2] = elf.ELFMAG2
        ehdr.e_ident[elf.EI_MAG3] = elf.ELFMAG3
        ehdr.e_ident[elf.EI_CLASS] = elf.ELFCLASS32
        ehdr.e_ident[elf.EI_DATA] = elf.ELFDATA2LSB
        ehdr.e_ident[elf.EI_VERSION] = elf.EV_CURRENT

        ehdr.e_type = elf.ET_CORE
        ehdr.e_machine = elf.EM_386
        ehdr.e_version = elf.EV_CURRENT
        ehdr.e_phoff = ctypes.sizeof(elf.Elf32_Ehdr())
        ehdr.e_ehsize = ctypes.sizeof(elf.Elf32_Ehdr())
        ehdr.e_phentsize = ctypes.sizeof(elf.Elf32_Phdr())
        ehdr.e_phnum = len(phdrs)

        return ehdr

    def generate_coredump(self):
        """
        Generate core dump for pid.
        """

        # Generate everything backwards so it is easier to calculate offset.
        self.vmas = self.gen_vmas()
        if not self.x86:
            self.notes = self.gen_notes()
            self.phdrs = self.gen_phdrs(self.notes, self.vmas)
            self.ehdr = self.gen_ehdr(self.phdrs)
        else:
            self.notes = self.gen_notes_x86()
            self.phdrs = self.gen_phdrs(self.notes, self.vmas)
            self.ehdr = self.gen_ehdr_x86(self.phdrs)
        self.shdrs = []

        return

    def write(self, buf):
        """
        Write core dump to file f.
        """

        section_header_start = sum(map(lambda x: x.filesz, self.vmas)) + ctypes.sizeof(elf.Elf64_Shdr)
        section_header_start += sum(map(lambda x: ctypes.sizeof(x), self.phdrs))
        for note in self.notes:
            section_header_start += ctypes.sizeof(note.nhdr)
            section_header_start += ctypes.sizeof(note.data)
            section_header_start += 8
        if self.x86 is True:
            offset = ctypes.sizeof(elf.Elf32_Ehdr())
            offset += (len(self.vmas) + 1) * ctypes.sizeof(elf.Elf32_Phdr())
        else:
            offset = ctypes.sizeof(elf.Elf64_Ehdr())
            offset += (len(self.vmas) + 1) * ctypes.sizeof(elf.Elf64_Phdr())

        filesz = 0

        for note in self.notes:
            filesz += ctypes.sizeof(note.nhdr) + ctypes.sizeof(note.data) + 8

        note_align = PAGESIZE - ((offset + filesz) % PAGESIZE)

        if note_align == PAGESIZE:
            note_align = 0

        section_header_start += note_align

        string_table = b'\0' + ".shstrtab".encode("utf-8") + b'\0' + "note0".encode("utf-8") + b'\0' \
                       + "load".encode("utf-8") + b'\0'
        section_header_start += len(string_table)

        self.ehdr.e_shoff = section_header_start
        self.ehdr.e_shentsize = ctypes.sizeof(elf.Elf64_Shdr)
        self.ehdr.e_shnum = 3 + len(self.vmas)
        self.ehdr.e_shstrndx = self.ehdr.e_shnum - 1

        current_offset = buf.write(self.ehdr)

        shdr = elf.Elf64_Shdr()
        shdr.sh_name = 0
        shdr.sh_type = 0
        shdr.sh_addr = 0
        shdr.sh_offset = 0
        shdr.sh_size = 0
        self.shdrs.append(shdr)

        for phdr in self.phdrs:
            current_offset += buf.write(phdr)

        note_size = 0
        for note in self.notes:
            note_size += buf.write(note.nhdr)
            note_size += buf.write(note.owner.encode('utf-8'))
            note_size += buf.write(b'\0' * (8 - len(note.owner)))
            note_size += buf.write(note.data)

        if note_align != 0:
            scratch = (ctypes.c_char * note_align)()
            ctypes.memset(ctypes.addressof(scratch), 0, ctypes.sizeof(scratch))
            note_size += buf.write(scratch)

        shdr = elf.Elf64_Shdr()
        shdr.sh_name = 11
        shdr.sh_type = 7  # -> note
        shdr.sh_addr = 0
        shdr.sh_offset = current_offset
        shdr.sh_size = note_size
        shdr.sh_flags = 2  # -> allocate
        shdr.sh_addralign = 1
        self.shdrs.append(shdr)

        current_offset += note_size

        counter = 0
        for vma in self.vmas:
            print(f"Writing pages for vma index {counter}")
            counter += 1

            shdr = elf.Elf64_Shdr()
            shdr.sh_name = 17
            shdr.sh_type = 1  # -> progbits
            shdr.sh_addr = vma.start
            shdr.sh_offset = current_offset
            shdr.sh_flags = self.get_shdr_flags(vma.flags)
            shdr.sh_addralign = 1

            vma_size = 0
            for page in vma.data.generate():
                vma_size += buf.write(page)

            shdr.sh_size = vma_size

            self.shdrs.append(shdr)
            current_offset += vma_size
            buf.flush()

        shdr = elf.Elf64_Shdr()
        shdr.sh_name = 1
        shdr.sh_type = 3  # -> STRTAB
        shdr.sh_addr = 0
        shdr.sh_offset = current_offset
        shdr.sh_size = len(string_table)
        shdr.sh_flags = 2  # -> SHF_ALLOC
        shdr.sh_addralign = 1
        self.shdrs.append(shdr)

        buf.write(string_table)

        for shdr in self.shdrs:
            buf.write(shdr)
        buf.flush()
