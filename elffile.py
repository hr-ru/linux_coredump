#!/usr/bin/env python -3
# -*- coding: utf-8 -*-
#
# Copyright 2010 - 2011 K. Richard Pixley.
# See LICENSE for details.
#
# Time-stamp: <01-Jul-2013 10:41:57 PDT by rich@noir.com>

"""
Elffile is a library which reads and writes `ELF format object files
<http://en.wikipedia.org/wiki/Executable_and_Linkable_Format>`.
Elffile is pure `python <http://python.org>`_ so installation is easy.

.. note:: while this library uses some classes as abstract base
    classes, it does not use :py:mod:`abc`.

.. todo:: need a "copy" method

.. todo:: need a reverse write method, (for testing)

"""

__docformat__ = 'restructuredtext en'

import functools
import io
import mmap
import operator
import os
import struct
import logging
import sys
from enum import Enum, IntEnum

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, format="%(levelname)-8s [%(filename)s:%(lineno)d] %(message)s")
logger = logging.getLogger("elffile")


def open(name=None, fileobj=None, map=None, block=None):
    """

    The open function takes some form of file identifier and creates
    an :py:class:`ElfFile` instance from it.

    :param :py:class:`str` name: a file name
    :param :py:class:`file` fileobj: if given, this overrides *name*
    :param :py:class:`mmap.mmap` map: if given, this overrides *fileobj*
    :param :py:class:`bytes` block: file contents in a block of memory, (if given, this overrides *map*)

    The file to be used can be specified in any of four different
    forms, (in reverse precedence):

    #. a file name
    #. :py:class:`file` object
    #. :py:mod:`mmap.mmap`, or
    #. a block of memory
    """

    if block:
        if not name:
            name = '<unknown>'

        efi = ElfFileIdent()
        efi.unpack_from(block)

        ef = ElfFile.encodedClass(efi)(name, efi)
        ef.unpack_from(block)

        if fileobj:
            fileobj.close()

        return ef

    if map:
        block = map

    elif fileobj:
        map = mmap.mmap(fileobj.fileno(), 0, access=mmap.ACCESS_READ)

    elif name:
        fileobj = io.open(os.path.normpath(os.path.expanduser(name)), 'rb')

    else:
        assert False

    return open(name=name,
                fileobj=fileobj,
                map=map,
                block=block)


class StructBase(object):
    """
    An abstract base class representing objects which are inherently
    based on a struct.
    """

    coder = None
    """
    The :py:class:`struct.Struct` used to encode/decode this object
    into a block of memory.  This is expected to be overridden by
    subclasses.
    """

    class _Size(object):
        def __get__(self, obj, t):
            return t.coder.size

    size = _Size()
    """
    Exact size in bytes of a block of memory into which is suitable
    for packing this instance.
    """

    def unpack(self, block):
        return self.unpack_from(block)

    def unpack_from(self, block, offset=0):
        """
        Set the values of this instance from an in-memory
        representation of the struct.

        :param string block: block of memory from which to unpack
        :param int offset: optional offset into the memory block from
            which to start unpacking
        """
        raise NotImplementedError

    def pack(self):
        x = bytearray(self.size)
        self.pack_into(x)
        return x

    def pack_into(self, block: bytearray, offset=0):
        """
        Store the values of this instance into an in-memory
        representation of the file.

        :param string block: block of memory into which to pack
        :param int offset: optional offset into the memory block into
            which to start packing
        """
        raise NotImplementedError

    __hash__ = None

    def __eq__(self, other):
        raise NotImplementedError

    def __ne__(self, other):
        return not self.__eq__(other)

    def close_enough(self, other):
        """
        This is a comparison similar to __eq__ except that here the
        goal is to determine whether two objects are "close enough"
        despite perhaps having been produced at different times in
        different locations in the file system.
        """
        return self == other


EI_NIDENT = 16
"""
Length of the byte-endian-independent, word size independent initial
portion of the ELF header file.  This is the portion represented by
:py:class:`ElfFileIdent`.
"""


class ElfFileIdent(StructBase):
    """
    This class corresponds to the first, byte-endian-independent,
    values in an elf file.  These tell us about the encodings for the
    rest of the file.  This is the *e_ident* field of the `elf file
    header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.

    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`coding.Coding` subclasses.
    """

    magic = None
    """
    The magic 'number' which should be '\x7fELF' for all ELF format files. 
    """

    elfClass = None
    """
    The 'class', (sic), of the file which represents whether the file
    is 32-bit or 64-bit.  Encoded using :py:class:`ElfClass`.
    """

    elfData = None
    """
    The 'data', (sic), of the file which represents the endian-ness
    used to encode this file.  Encoded using :py:class:`ElfData`.
    """

    fileVersion = None
    """
    The version of the ELF format used to encode this file.  Must be
    :py:const:`EV_CURRENT`.  Encoded using :py:class:`EV`.
    """

    osabi = None
    """
    Represents the operating system for which this ELF file is
    intended.  Encoded using :py:class:`ElfOsabi`.
    """

    abiversion = None
    """
    Represents the version of the operating system ABI format used by
    this ELF file.
    """

    coder = struct.Struct(b'=4sBBBBBxxxxxxx')
    """
    A :py:class:`struct.Struct` (de)coder involving six fields:

    * '\x7fELF', (Elf file magic number)
    * ElfClass (32 vs 64-bit)
    * ElfData (endianness)
    * EV (file version)
    * ElfOsabi (operating system)
    * abiversion
    """

    # size is EI_IDENT
    assert (coder.size == EI_NIDENT), 'coder.size = {0}({0}), EI_NIDENT = {0}({0})'.format(coder.size, type(coder.size),
                                                                                           EI_NIDENT, type(EI_NIDENT))

    def unpack_from(self, block, offset=0):
        (self.magic, self.elfClass, self.elfData, self.fileVersion, self.osabi,
         self.abiversion) = self.coder.unpack_from(block, offset)
        return self

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset, self.magic, self.elfClass.value,
                             self.elfData.value, self.fileVersion.value,
                             self.osabi.value, self.abiversion)

        return self

    def __repr__(self):
        return (
            '<{0}@{1}: coder={2}, magic=\'{3}\', elfClass={4}, elfData={5}, fileVersion={6}, osabi={7}, abiversion={8}>'
            .format(self.__class__.__name__, hex(id(self)), self.coder, self.magic,
                    self.elfClass.name if self.elfClass else None,
                    self.elfData.name if self.elfData else None,
                    self.fileVersion, self.osabi, self.abiversion))

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
                and self.coder == other.coder
                and self.magic == other.magic
                and self.elfClass == other.elfClass
                and self.elfData == other.elfData
                and self.fileVersion == other.fileVersion
                and self.osabi == other.osabi
                and self.abiversion == other.abiversion)

    close_enough = __eq__

    def _list_encode(self):
        return (self.__class__.__name__,
                hex(id(self)),
                {
                    'coder': self.coder,
                    'magic': self.magic,
                    'elfClass': ElfClass(self.elfClass).name,
                    'elfData': ElfData(self.elfData).name,
                    'fileVersion': self.fileVersion,
                    'osabi': self.osabi,
                    'abiversion': self.abiversion,
                })


class ElfClass(IntEnum):
    """
    Encodes the word size of the elf file as from the `ident portion
    of the ELF file header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfFileIdent.elfClass`.
    """
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2
    ELFCCLASSSNUM = 3


class ElfData(Enum):
    """
    Encodes the byte-wise endianness of the elf file as from the
    `ident portion of the elf file header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.
    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfFileIdent.elfData`.
    """
    ELFDATANONE = 0
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2
    ELFDATANUM = 3


class EV(Enum):
    """
    Encodes the elf file format version of this elf file as from the `ident portion of the elf file
    header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.  This is a subclass of :py:class:`coding.Coding`.
    """
    EV_NONE = 0
    EV_CURRENT = 1
    EV_NUM = 2


class ElfOsabi(Enum):
    """
    Encodes OSABI values which represent operating system ELF format
    extensions as from the `'ident' portion of the elf file header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>`_.

    This is a subclass of :py:class:`coding.Coding` which codes :py:attr:`ElfFileIdent.osabi`.
    """
    # overload_codes = True
    ELFOSABI_NONE = 0
    ELFOSABI_SYSV = 0
    ELFOSABI_HPUX = 1
    ELFOSABI_NETBSD = 2
    ELFOSABI_LINUX = 3
    ELFOSABI_SOLARIS = 6
    ELFOSABI_AIX = 7
    ELFOSABI_IRIX = 8
    ELFOSABI_FREEBSD = 9
    ELFOSABI_TRU64 = 10
    ELFOSABI_MODESTO = 11
    ELFOSABI_OPENBSD = 12
    ELFOSABI_OPENVMS = 13
    ELFOSABI_NSK = 14
    ELFOSABI_AROS = 15
    ELFOSABI_FENIXOS = 16
    ELFOSABI_ARM_EABI = 64
    ELFOSABI_ARM = 97
    ELFOSABI_STANDALONE = 255


class ElfFile(StructBase):
    """
    This class corresponds to an entire ELF format file.  It is an
    abstract base class which is not intended to be instantiated but
    rather subclassed.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfFile32b`, :py:class:`ElfFile32l`,
    :py:class:`ElfFile64b`, and :py:class:`ElfFile64l`.  This abstract
    base class sets useless defaults and includes byte order and word
    size independent methods while the subclasses define byte order
    and word size dependent methods.
    """

    name = None
    """
    A :py:class:`str` containing the file name for this ELF format
    object file.
    """

    fileIdent = None
    """
    A :py:class:`ElfFileIdent` representing the :c:data:`e_ident`
    portion of the ELF format file header.
    """

    fileHeader = None
    """
    A :py:class:`ElfFileHeader` representing the byte order and word
    size dependent portion of the ELF format file header.
    """

    sectionHeaders = []
    """
    A :py:class:`list` of section headers.  This corresponds to the
    section header table.
    """

    programHeaders = []
    """
    A :py:class:`list` of the program headers.  This corresponds to
    the program header table.
    """

    fileHeaderClass = None
    """
    Intended to be set by the subclasses.  Points to the byte order
    and word size sensitive class to be used for the ELF file header.
    """

    class NO_CLASS(Exception):
        """
        Raised when attempting to decode an unrecognized value for
        :py:class:`ElfClass`, (that is, word size).
        """
        pass

    class NO_ENCODING(Exception):
        """
        Raised when attempting to decode an unrecognized value for
        :py:class:`ElfData`, (that is, byte order).
        """

    @staticmethod
    def encodedClass(ident):
        """
        :param :py:class:`ElfFileIdent`:  This is
        :rtype :py:class:`ElfFile`: broken
        .. todo:: file sphinx bug on this once code is released so that they can see it.

        Given an *ident*, return a suitable :py:class:`ElfFile` subclass to represent that file.

        Raises :py:exc:`NO_CLASS` if the :py:class:`ElfClass`, (word size), cannot be represented.

        Raises :py:exc:`NO_ENCODING` if the :py:class:`ElfData`, (byte order), cannot be represented.
        """
        classcode = ident.elfClass.value
        if classcode in _fileEncodingDict:
            elfclass = _fileEncodingDict[classcode]
        else:
            raise ElfFile.NO_CLASS

        endiancode = ident.elfData.value
        if endiancode in elfclass:
            return elfclass[endiancode]
        else:
            raise ElfFile.NO_ENCODING

    def __new__(cls, name, fileIdent):
        assert fileIdent

        if cls != ElfFile:
            return object.__new__(cls)

        retval = ElfFile.__new__(ElfFile.encodedClass(fileIdent), name, fileIdent)
        retval.__init__(name, fileIdent)
        return retval

    def __init__(self, name, fileIdent):
        """
        :param :py:class:`str` name
        :param :py:class:`ElfFileIdent`
        """

        self._offsets = None
        self.name = name

        self.fileIdent = fileIdent
        self.fileHeader = None
        self.sectionHeaders = []
        self.programHeaders = []

    def unpack_from(self, block, offset=0):
        """
        Unpack an entire file.

        .. todo:: I don't understand whether segments overlap sections
            or not.
        """

        self._unpack_fileIdent(block, offset)
        self._unpack_file_header(block, offset)
        self._unpack_section_headers(block, offset)
        self._unpack_sections(block, offset)
        self._unpack_section_names()
        self._unpack_program_headers(block, offset)
        self._unpack_segments(block, offset)

        return self

    def _unpack_fileIdent(self, block, offset):
        if not self.fileIdent:
            self.fileIdent = ElfFileIdent()

        self.fileIdent.unpack_from(block, offset)

    def _unpack_file_header(self, block, offset):
        if not self.fileHeader:
            self.fileHeader = self.fileHeaderClass()

        self.fileHeader.unpack_from(block, offset + self.fileIdent.size)

    def _unpack_section_headers(self, block, offset):
        # section headers
        if self.fileHeader.shoff != 0:
            sectionCount = self.fileHeader.shnum

            self.sectionHeaders.append(self.sectionHeaderClass().unpack_from(block, offset + self.fileHeader.shoff))

            if sectionCount == 0:
                sectionCount = self.sectionHeaders[0].section_size

            for i in range(1, sectionCount):
                self.sectionHeaders.append(self.sectionHeaderClass().unpack_from(block,
                                                                                 offset + self.fileHeader.shoff
                                                                                 + (i * self.fileHeader.shentsize)))

    def _unpack_sections(self, block, offset):
        for sh in self.sectionHeaders:
            sh.content = block[offset + sh.offset:offset + sh.offset + sh.section_size]  # section contents are copied

    def _unpack_section_names(self):
        # little tricky here - can't read section names until after
        # that section has been read.  So effectively this is two pass.

        for section in self.sectionHeaders:
            section.name = self.sectionName(section)

    def _unpack_program_headers(self, block, offset):
        if self.fileHeader.phoff != 0:
            segmentCount = self.fileHeader.phnum

            self.programHeaders.append(self.programHeaderClass().unpack_from(block, offset + self.fileHeader.phoff))

            if segmentCount == ElfProgramHeader.PN_XNUM:
                segmentCount = self.sectionHeaders[0].info

            for i in range(1, segmentCount):
                self.programHeaders.append(self.programHeaderClass().unpack_from(block,
                                                                                 offset + self.fileHeader.phoff
                                                                                 + (i * self.fileHeader.phentsize)))

    def _unpack_segments(self, block, offset):
        for ph in self.programHeaders:
            ph.content = block[offset + ph.offset:offset + ph.offset + ph.filesz]  # segment contents are copied

    def pack_into(self, block, offset=0):
        """
        Pack the entire file.  Rewrite offsets as necessary.
        """
        if not self._offsets:
            self._offsets = self.calculate_offsets(offset)
        total, scoff, shoff, pcoff, phoff = self._offsets
        # section name table regeneration is done on calculate_offsets alread
        # self._regen_section_name_table()
        self._pack_file_header(block, offset, shoff, phoff)
        self._pack_program_headers(block, phoff)
        self._pack_sections(block, scoff)
        self._pack_section_headers(block, shoff)

    def calculate_offsets(self, offset=0):
        """
        Current packing layout is:

        * fileIdent + fileHeader
        * program header
        * section contents
        * sectionHeaders
        """
        logger.debug("Calculating offsets")
        # We have to regenerate the section name table here, because this decides the size of the section name table
        self._regen_section_name_table()
        self.fileHeader.shnum = len(self.sectionHeaders)
        self.fileHeader.phnum = len(self.programHeaders)

        # First the ELF header (ident+fileheader)
        x = offset
        x += self.fileHeader.ehsize

        # Next the program headers
        phoff = x
        x += (len(self.programHeaders) * self.fileHeader.phentsize)

        # Then the section contents
        scoff = x
        for i in self.sectionHeaders[1:]:
            i.offset = x
            if hasattr(i, "_ph"):
                i._ph.offset = x
            logger.debug("Section at offset %x with size %x, addr: %x", x, i.section_size, i.offset)
            x += i.section_size

        # Finally the section headers
        shoff = x
        x += (len(self.sectionHeaders) * self.fileHeader.shentsize)

        # TODO: This was here in the old code, but no idea what it was meant to be good for.
        pcoff = x
        for i in self.programHeaders:
            x += 0

        total = x
        logger.debug("Offset: program headers=0x%x, sections=0x%s, section headers=0x%x, pcoff=0x%x, end=0x%x",
                      phoff, scoff, shoff, pcoff, total)
        self._offsets = (total, scoff, shoff, pcoff, phoff)
        return self._offsets

    def _regen_section_name_table(self):
        """
        (Re)build the section name table section.
        """

        # rewrite existing section.  If none exists, we append a new section name table section (snts)
        if not self.fileHeader.shstrndx:
            logger.debug("Creating new section name table section")
            snts = self.sectionHeaderClass()
            snts.type = SHT.SHT_STRTAB
            snts.name = b'.shstrtab'
            snts.addr = 0
            snts.addralign = 1
            snts.entsize = 0
            snts.flags = 0
            snts.info = 0
            snts.link = 0
            self.sectionHeaders.append(snts)
            self.fileHeader.shstrndx = len(self.sectionHeaders) - 1

        section = self.sectionHeaders[self.fileHeader.shstrndx]

        # We could merge pointers to same strings and/or common suffixes, but let's keep it simple

        # Total size is sum of the sizes of all of the names (plus \0 at the end) plus initial null
        section.section_size = functools.reduce(operator.__add__, [len(sh.name)+1 for sh in self.sectionHeaders]) + 1

        # HPR: the original code was "contents", but this should be "content"!
        section.content = bytearray(section.section_size)
        p = 0
        section.content[p] = 0
        p += 1

        for sh in self.sectionHeaders:
            namelen = len(sh.name)
            section.content[p:p + namelen] = sh.name  # was: [p:namelen], which does not make sense
            sh.nameoffset = p  # was: section.nameoffset = p
            p += namelen
            section.content[p] = 0  # HPR: original code was [namelenl], which does not make any sense here
            p += 1

        logger.debug("Updated section name table section, len=%d, entries=%d (%s)", section.section_size,
                     len(self.sectionHeaders), ";".join([x.name.decode('utf-8') for x in self.sectionHeaders]))

    def _pack_file_header(self, block, offset, shoff, phoff):
        """
        Determine and set current offsets then pack the file header.
        """
        self.fileIdent.pack_into(block, offset)

        self.fileHeader.shoff = shoff if len(self.sectionHeaders) > 0 else 0
        self.fileHeader.phoff = phoff if len(self.programHeaders) > 0 else 0
        self.fileHeader.pack_into(block, offset + self.fileIdent.size)

    def _pack_sections(self, block, offset=0):
        """
        Pack the section contents.  As a side effect, set the offsets
        in the section headers telling where we put them and the
        section_sizes telling how much we put.
        """
        p = offset
        # skipping the NULL section...
        for section in self.sectionHeaders[1:]:
            startp = p
            section.offset = p
            newlen = len(section.content)
            diff = ""
            if newlen != section.section_size: diff = "(was "+str(section.section_size)+" before update)"
            logger.debug("Packing section at offset %x, size is %x %s", p, newlen, diff)
            section.section_size = newlen
            if isinstance(section.content, bytearray) or isinstance(section.content, bytes):
                block[p:p + section.section_size] = section.content
                p += section.section_size
            else:
                psize = 0
                # its a generator
                for page in section.content.generate():
                    if not page == b'\0' * len(page):
                        block[p:p + len(page)] = page
                        psize += len(page)
                    p += len(page)
                if psize == 0:
                    logger.debug("section content is all zero, removing section")
                    p = startp  # skip this section, as it is all ZERO
                    section.section_size = 0
                    section.content = bytearray(0)
                elif psize != section.section_size:
                    logger.debug("Physical (non-zero) section content size is %x", psize)

    def _pack_section_headers(self, block, offset):
        """
        Pack the section header table.

        .. todo:: first section header is reserved and should be all
            zeros.  Need to verify this and/or force one.
        """
        shiter = zip(range(0, len(self.sectionHeaders)), self.sectionHeaders)
        for i, sh in shiter:
            sh.pack_into(block, offset + (i * self.fileHeader.shentsize))

    def _pack_program_headers(self, block, offset):
        """
        Pack the section header table.

        """
        shiter = zip(range(0, len(self.programHeaders)), self.programHeaders)
        for i, ph in shiter:
            ph.pack_into(block, offset + (i * self.fileHeader.phentsize))

    @property
    def size(self):
        if not self._offsets:
            self._offsets = self.calculate_offsets(0)
        return self._offsets[0]

    def sectionName(self, section):
        """
        Given a section, return it's name.

        :param :py:class:`ElfSectionHeader` section:
        """
        x = self.sectionHeaders[self.fileHeader.shstrndx].content
        return x[section.nameoffset:x.find(b'\0', section.nameoffset)]

    def __eq__(self, other):
        """
         .. todo:: it would not be difficult to break up the string
            table, sort, and compare the results.  But then we'll also
            need a way to stub out the embedded path names.
        """

        if not isinstance(other, self.__class__):
            return False

        if (self.fileIdent != other.fileIdent
                or self.fileHeader != other.fileHeader):
            return False

        # FIXME: need to handle order independence
        for this, that in zip(self.sectionHeaders, other.sectionHeaders):
            if this != that:
                import sys
                print('{0} differs from {1}'.format(this, that), file=sys.stderr)
                return False

        return True

    def close_enough(self, other):
        """
        .. todo:: it would not be difficult to break up the string
            table, sort, and compare the results.  But then we'll also
            need a way to stub out the embedded path names.
        """

        if not isinstance(other, self.__class__):
            return False

        if ((not self.fileIdent.close_enough(other.fileIdent))
                or (not self.fileHeader.close_enough(other.fileHeader))):
            return False

        # FIXME: need to handle order independence
        for this, that in zip(self.sectionHeaders, other.sectionHeaders):
            if (this.name in [
                '.ARM.attributes',
                '.ARM.exidx',
                '.ARM.extab',
                '.comment',
                '.debug_aranges',
                '.debug_frame',
                '.debug_info',  # x86_64 linux dyn
                '.debug_line',  # arm debug lines contain file names
                '.debug_loc',
                '.debug_pubnames',
                '.debug_ranges',
                '.debug_str',  # x86_64 linux rela
                '.gnu_debuglink',  # arm: maybe time stamps?
                '.note.GNU-stack',
                '.note.gnu.build-id',  # x86_64 linux dyn
                '.rel.ARM.exidx',
                '.rel.debug_aranges',
                '.rel.debug_frame',
                '.rel.debug_info',  # x86_64 linux rela
                '.rel.debug_line',
                '.rel.debug_pubnames',
                '.rel.text',
                '.rodata',
                '.rodata.str1.4',
                '.shstrtab',
                '.strtab',
                '.symtab',
            ]
                    or this.type == SHT.SHT_NOBITS  # Not sure what this is or why it differs
            ):
                continue

            if not this.close_enough(that):
                import sys
                print('section({0}) not close enough to section({1})'.format(this.name, that.name), file=sys.stdout)
                return False

        return True

    def __repr__(self):
        return ('<{0}@{1}: name=\'{2}\', fileIdent={3}, fileHeader={4}>'
                .format(self.__class__.__name__, hex(id(self)), self.name, self.fileIdent, self.fileHeader))

    def _list_encode(self):
        return (self.__class__.__name__,
                hex(id(self)),
                {
                    'name': self.name,
                    'fileIdent': self.fileIdent._list_encode(),
                    'fileHeader': self.fileHeader._list_encode(),
                    'sectionHeaders': [sh._list_encode() for sh in self.sectionHeaders],
                    'programHeaders': [ph._list_encode() for ph in self.programHeaders],
                })


class ElfFileHeader(StructBase):
    """
    This abstract base class corresponds to the portion of the `ELF
    file header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_
    which follows :c:data:`e_ident`, that is, the word size and byte
    order dependent portion.  This includes thirteen fields.

    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`coding.Coding` subclasses.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfFileHeader32b`,
    :py:class:`ElfFileHeader32l`, :py:class:`ElfFileHeader64b`, and
    :py:class:`ElfFileHeader64l`.  This base class sets useless
    defaults and includes any byte order and word size independent
    methods while the subclasses define byte order and word size
    dependent methods.
    """

    type = None
    """
    The 'type', (sic), of the file which represents whether this file
    is an executable, relocatable object, shared library, etc.
    Encoded using :py:class:`ET`.
    """

    machine = None
    """
    Specifies the processor architecture of the file.  Encoded using :py:class:`EM`.
    """

    version = None
    """
    Specifies the version of the ELF format used for this file.
    Should be 1 in most cases.  Extensions are expected to increment
    the number.
    """

    entry = None
    """
    Virtual start address when this file is converted into a process.
    Zero if not used.
    """

    phoff = None
    """
    Offset in bytes into this file at which the program header table,
    (:py:class:`ElfProgramHeader`), starts.
    """

    shoff = None
    """
    Offset in bytes into this file at which the section header table,
    (:py:class:`ElfSectionHeader`), starts.
    """

    flags = None
    """
    Any processor specific flags for this file.
    """

    ehsize = None
    """
    Size in bytes of the ELF file header, (:py:class:`ElfFileHeader`),
    as represented in this file.
    """

    phentsize = None
    """
    Size in bytes of a program header table entry,
    (:py:class:`ElfProgramHeader`), as represented in this file.  All
    entries are the same size.
    """

    phnum = None
    """
    A count of the number of program header table entries,
    (:py:class:`ElfProgramHeader`), in this file.
    """

    shentsize = None
    """
    Size in bytes of a section table entry,
    (:py:class:`ElfSectionHeader`), as represented in this file.  All
    entries aer the same size.
    """

    shnum = None
    """
    A count of the number of section header table entries,
    (:py:class:`ElfSectionHeader`), in this file.
    """

    shstrndx = None
    """
    The section header table index of the section name string table.
    (SHN_UNDEF if there is none).
    """

    def unpack_from(self, block, offset=0):
        (self.type, self.machine, self.version, self.entry,
         self.phoff, self.shoff, self.flags, self.ehsize,
         self.phentsize, self.phnum, self.shentsize, self.shnum,
         self.shstrndx) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset, self.type.value, self.machine.value,
                             self.version if self.version != None else 1,
                             self.entry if self.entry != None else 0,
                             self.phoff if self.phoff != None else 0,
                             self.shoff if self.shoff != None else 0,
                             self.flags if self.flags != None else 0,
                             self.ehsize if self.ehsize != None else self.size,
                             self.phentsize if self.phentsize != None else self.programHeaderClass.size,
                             self.phnum if self.phnum != None else 0,
                             self.shentsize if self.shentsize != None else self.sectionHeaderClass.size,
                             self.shnum if self.shnum != None else 0,
                             self.shstrndx if self.shstrndx != None else 0)

        return self

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
                and self.type == other.type
                and self.machine == other.machine
                and self.version == other.version
                and self.entry == other.entry
                and self.phoff == other.phoff
                # and self.shoff == other.shoff
                and self.flags == other.flags
                and self.ehsize == other.ehsize
                and self.phentsize == other.phentsize
                and self.phnum == other.phnum
                and self.shentsize == other.shentsize
                and self.shnum == other.shnum
                and self.shstrndx == other.shstrndx)

    def close_enough(self, other):
        return (isinstance(other, self.__class__)
                and self.type == other.type
                and self.machine == other.machine
                and self.version == other.version
                and self.entry == other.entry
                and self.phoff == other.phoff
                and self.flags == other.flags
                and self.ehsize == other.ehsize
                and self.phentsize == other.phentsize
                and self.phnum == other.phnum
                and self.shentsize == other.shentsize
                and self.shnum == other.shnum
                and self.shstrndx == other.shstrndx)

    def __repr__(self):
        return ('<{0}@{1}: type={2}, machine={3}, version={4},'
                ' entry={5}, phoff={6}, shoff={7}, flags={8},'
                ' ehsize={9}, phnum={10}, shentsize={11}, shnum={12},'
                ' shstrndx={13}>'
                .format(self.__class__.__name__, hex(id(self)), ET(self.type).name, EM(self.machine).name,
                        self.version, hex(self.entry), self.phoff, self.shoff,
                        hex(self.flags), self.ehsize, self.phnum, self.shentsize,
                        self.shnum, self.shstrndx))

    def _list_encode(self):
        return (self.__class__.__name__,
                hex(id(self)),
                {
                    'type': ET(self.type).name,
                    'machine': EM(self.machine).name,
                    'version': self.version,
                    'entry': hex(self.entry),
                    'phoff': self.phoff,
                    'shoff': self.shoff,
                    'flags': hex(self.flags),
                    'ehsize': self.ehsize,
                    'phnum': self.phnum,
                    'shentsize': self.shentsize,
                    'shnum': self.shnum,
                    'shstrndx': self.shstrndx,
                })


class ElfFileHeader32b(ElfFileHeader):
    """
    A subclass of :py:class:`ElfFileHeader`.  This one represents
    32-bit, big-endian headers.
    """
    coder = struct.Struct(b'>HHIIIIIHHHHHH')


class ElfFileHeader32l(ElfFileHeader):
    """
    A subclass of :py:class:`ElfFileHeader`.  This one represents
    32-bit, little-endian headers.
    """
    coder = struct.Struct(b'<HHIIIIIHHHHHH')


class ElfFileHeader64b(ElfFileHeader):
    """
    A subclass of :py:class:`ElfFileHeader`.  This one represents
    64-bit, big-endian headers.
    """
    coder = struct.Struct(b'>HHIQQQIHHHHHH')


class ElfFileHeader64l(ElfFileHeader):
    """
    A subclass of :py:class:`ElfFileHeader`.  This one represents
    64-bit, little-endian headers.
    """
    coder = struct.Struct(b'<HHIQQQIHHHHHH')


class ET(IntEnum):
    """
    Encodes the type of this elf file, (relocatable, executable,
    shared library, etc.), as represented in the `ELF file header
    <http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_.
    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfFileHeader.type`.
    """
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4
    ET_NUM = 5
    ET_LOOS = 0xfe00
    ET_HIOS = 0xfeff
    ET_LOPROC = 0xff00
    ET_HIPROC = 0xffff


class EM(IntEnum):
    """
    Encodes the processor type represented in this elf file as
    recorded in the `ELF file header <http://www.sco.com/developers/gabi/latest/ch4.eheader.html>`_.

    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfFileHeader.machine`.
    """
    EM_NONE = 0  # 'No machine')
    EM_M32 = 1  # 'AT&T WE 32100')
    EM_SPARC = 2  # 'SPARC')
    EM_386 = 3  # 'Intel 80386')
    EM_68K = 4  # 'Motorola 68000')
    EM_88K = 5  # 'Motorola 88000')
    EM_486 = 6  # 'Reserved for future use (was EM_486)')
    EM_860 = 7  # 'Intel 80860')
    EM_MIPS = 8  # 'MIPS I Architecture')
    EM_S370 = 9  # 'IBM System/370 Processor')
    EM_MIPS_RS3_LE = 10  # 'MIPS RS3000 Little-endian')
    # 11 - 14 reserved
    EM_PARISC = 15  # 'Hewlett-Packard PA-RISC')
    # 16 reserved
    EM_VPP500 = 17  # 'Fujitsu VPP500')
    EM_SPARC32PLUS = 18  # 'Enhanced instruction set SPARC')
    EM_960 = 19  # 'Intel 80960')
    EM_PPC = 20  # 'PowerPC')
    EM_PPC64 = 21  # '64-bit PowerPC')
    EM_S390 = 22  # 'IBM System/390 Processor')
    EM_SPU = 23  # 'IBM SPU/SPC')
    # 24 - 35 reserved
    EM_V800 = 36  # 'NEC V800')
    EM_FR20 = 37  # 'Fujitsu FR20')
    EM_RH32 = 38  # 'TRW RH-32')
    EM_RCE = 39  # 'Motorola RCE')
    EM_ARM = 40  # 'Advanced RISC Machines ARM')
    EM_ALPHA = 41  # 'Digital Alpha')
    EM_SH = 42  # 'Hitachi SH')
    EM_SPARCV9 = 43  # 'SPARC Version 9')
    EM_TRICORE = 44  # 'Siemens TriCore embedded processor')
    EM_ARC = 45  # 'Argonaut RISC Core, Argonaut Technologies Inc.')
    EM_H8_300 = 46  # 'Hitachi H8/300')
    EM_H8_300H = 47  # 'Hitachi H8/300H')
    EM_H8S = 48  # 'Hitachi H8S')
    EM_H8_500 = 49  # 'Hitachi H8/500')
    EM_IA_64 = 50  # 'Intel IA-64 processor architecture')
    EM_MIPS_X = 51  # 'Stanford MIPS-X')
    EM_COLDFIRE = 52  # 'Motorola ColdFire')
    EM_68HC12 = 53  # 'Motorola M68HC12')
    EM_MMA = 54  # 'Fujitsu MMA Multimedia Accelerator')
    EM_PCP = 55  # 'Siemens PCP')
    EM_NCPU = 56  # 'Sony nCPU embedded RISC processor')
    EM_NDR1 = 57  # 'Denso NDR1 microprocessor')
    EM_STARCORE = 58  # 'Motorola Star*Core processor')
    EM_ME16 = 59  # 'Toyota ME16 processor')
    EM_ST100 = 60  # 'STMicroelectronics ST100 processor')
    EM_TINYJ = 61  # 'Advanced Logic Corp. TinyJ embedded processor family')
    EM_X86_64 = 62  # 'AMD x86-64 architecture')
    EM_PDSP = 63  # 'Sony DSP Processor')
    EM_PDP10 = 64  # 'Digital Equipment Corp. PDP-10')
    EM_PDP11 = 65  # 'Digital Equipment Corp. PDP-11')
    EM_FX66 = 66  # 'Siemens FX66 microcontroller')
    EM_ST9PLUS = 67  # 'STMicroelectronics ST9+ 8/16 bit microcontroller')
    EM_ST7 = 68  # 'STMicroelectronics ST7 8-bit microcontroller')
    EM_68HC16 = 69  # 'Motorola MC68HC16 Microcontroller')
    EM_68HC11 = 70  # 'Motorola MC68HC11 Microcontroller')
    EM_68HC08 = 71  # 'Motorola MC68HC08 Microcontroller')
    EM_68HC05 = 72  # 'Motorola MC68HC05 Microcontroller')
    EM_SVX = 73  # 'Silicon Graphics SVx')
    EM_ST19 = 74  # 'STMicroelectronics ST19 8-bit microcontroller')
    EM_VAX = 75  # 'Digital VAX')
    EM_CRIS = 76  # 'Axis Communications 32-bit embedded processor')
    EM_JAVELIN = 77  # 'Infineon Technologies 32-bit embedded processor')
    EM_FIREPATH = 78  # 'Element 14 64-bit DSP Processor')
    EM_ZSP = 79  # 'LSI Logic 16-bit DSP Processor')
    EM_MMIX = 80  # 'Donald Knuth\'s educational 64-bit processor')
    EM_HUANY = 81  # 'Harvard University machine-independent object files')
    EM_PRISM = 82  # 'SiTera Prism')
    EM_AVR = 83  # 'Atmel AVR 8-bit microcontroller')
    EM_FR30 = 84  # 'Fujitsu FR30')
    EM_D10V = 85  # 'Mitsubishi D10V')
    EM_D30V = 86  # 'Mitsubishi D30V')
    EM_V850 = 87  # 'NEC v850')
    EM_M32R = 88  # 'Mitsubishi M32R')
    EM_MN10300 = 89  # 'Matsushita MN10300')
    EM_MN10200 = 90  # 'Matsushita MN10200')
    EM_PJ = 91  # 'picoJava')
    EM_OPENRISC = 92  # 'OpenRISC 32-bit embedded processor')
    EM_ARC_COMPACT = 93  # 'ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)')
    EM_XTENSA = 94  # 'Tensilica Xtensa Architecture')
    EM_VIDEOCORE = 95  # 'Alphamosaic VideoCore processor')
    EM_TMM_GPP = 96  # 'Thompson Multimedia General Purpose Processor')
    EM_NS32K = 97  # 'National Semiconductor 32000 series')
    EM_TPC = 98  # 'Tenor Network TPC processor')
    EM_SNP1K = 99  # 'Trebia SNP 1000 processor')
    EM_ST200 = 100  # 'STMicroelectronics (www.st.com) ST200 microcontroller')
    EM_IP2K = 101  # 'Ubicom IP2xxx microcontroller family')
    EM_MAX = 102  # 'MAX Processor')
    EM_CR = 103  # 'National Semiconductor CompactRISC microprocessor')
    EM_F2MC16 = 104  # 'Fujitsu F2MC16')
    EM_MSP430 = 105  # 'Texas Instruments embedded microcontroller msp430')
    EM_BLACKFIN = 106  # 'Analog Devices Blackfin (DSP) processor')
    EM_SE_C33 = 107  # 'S1C33 Family of Seiko Epson processors')
    EM_SEP = 108  # 'Sharp embedded microprocessor')
    EM_ARCA = 109  # 'Arca RISC Microprocessor')
    EM_UNICORE = 110  # 'Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University')
    EM_EXCESS = 111  # 'eXcess: 16/32/64-bit configurable embedded CPU')
    EM_DXP = 112  # 'Icera Semiconductor Inc. Deep Execution Processor')
    EM_ALTERA_NIOS2 = 113  # 'Altera Nios II soft-core processor')
    EM_CRX = 114  # 'National Semiconductor CompactRISC CRX microprocessor')
    EM_XGATE = 115  # 'Motorola XGATE embedded processor')
    EM_C166 = 116  # 'Infineon C16x/XC16x processor')
    EM_M16C = 117  # 'Renesas M16C series microprocessors')
    EM_DSPIC30F = 118  # 'Microchip Technology dsPIC30F Digital Signal Controller')
    EM_CE = 119  # 'Freescale Communication Engine RISC core')
    EM_M32C = 120  # 'Renesas M32C series microprocessors')
    # 121 - 130 reserved
    EM_TSK3000 = 131  # 'Altium TSK3000 core')
    EM_RS08 = 132  # 'Freescale RS08 embedded processor')
    # 133 reserved
    EM_ECOG2 = 134  # 'Cyan Technology eCOG2 microprocessor')
    EM_SCORE7 = 135  # 'Sunplus S+core7 RISC processor')
    EM_DSP24 = 136  # 'New Japan Radio (NJR) 24-bit DSP Processor')
    EM_VIDEOCORE3 = 137  # 'Broadcom VideoCore III processor')
    EM_LATTICEMICO32 = 138  # 'RISC processor for Lattice FPGA architecture')
    EM_SE_C17 = 139  # 'Seiko Epson C17 family')
    EM_TI_C6000 = 140  # 'The Texas Instruments TMS320C6000 DSP family')
    EM_TI_C2000 = 141  # 'The Texas Instruments TMS320C2000 DSP family')
    EM_TI_C5500 = 142  # 'The Texas Instruments TMS320C55x DSP family')
    # 143 - 159 reserved
    EM_MMDSP_PLUS = 160  # 'STMicroelectronics 64bit VLIW Data Signal Processor')
    EM_CYPRESS_M8C = 161  # 'Cypress M8C microprocessor')
    EM_R32C = 162  # 'Renesas R32C series microprocessors')
    EM_TRIMEDIA = 163  # 'NXP Semiconductors TriMedia architecture family')
    EM_QDSP6 = 164  # 'QUALCOMM DSP6 Processor')
    EM_8051 = 165  # 'Intel 8051 and variants')
    EM_STXP7X = 166  # 'STMicroelectronics STxP7x family of configurable and extensible RISC processors')
    EM_NDS32 = 167  # 'Andes Technology compact code size embedded RISC processor family')
    EM_ECOG1 = 168  # 'Cyan Technology eCOG1X family')
    EM_ECOG1X = 168  # 'Cyan Technology eCOG1X family')
    EM_MAXQ30 = 169  # 'Dallas Semiconductor MAXQ30 Core Micro-controllers')
    EM_XIMO16 = 170  # 'New Japan Radio (NJR) 16-bit DSP Processor')
    EM_MANIK = 171  # 'M2000 Reconfigurable RISC Microprocessor')
    EM_CRAYNV2 = 172  # 'Cray Inc. NV2 vector architecture')
    EM_RX = 173  # 'Renesas RX family')
    EM_METAG = 174  # 'Imagination Technologies META processor architecture')
    EM_MCST_ELBRUS = 175  # 'MCST Elbrus general purpose hardware architecture')
    EM_ECOG16 = 176  # 'Cyan Technology eCOG16 family')
    EM_CR16 = 177  # 'National Semiconductor CompactRISC CR16 16-bit microprocessor')
    EM_ETPU = 178  # 'Freescale Extended Time Processing Unit')
    EM_SLE9X = 179  # 'Infineon Technologies SLE9X core')
    # 180-182 Reserved for future Intel use
    # 183-184 Reserved for future ARM use
    EM_AVR32 = 185  # 'Atmel Corporation 32-bit microprocessor family')
    EM_STM8 = 186  # 'STMicroeletronics STM8 8-bit microcontroller')
    EM_TILE64 = 187  # 'Tilera TILE64 multicore architecture family')
    EM_TILEPRO = 188  # 'Tilera TILEPro multicore architecture family')
    EM_MICROBLAZE = 189  # 'Xilinx MicroBlaze 32-bit RISC soft processor core')
    EM_CUDA = 190  # 'NVIDIA CUDA architecture')
    EM_TILEGX = 191  # 'Tilera TILE-Gx multicore architecture family')
    EM_CLOUDSHIELD = 192  # 'CloudShield architecture family')
    EM_COREA_1ST = 193  # 'KIPO-KAIST Core-A 1st generation processor family')
    EM_COREA_2ND = 194  # 'KIPO-KAIST Core-A 2nd generation processor family')


class ElfSectionHeader(StructBase):
    """
    This abstract base class corresponds to an entry in `the section
    header table
    <http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.
    This includes ten fields.

    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`coding.Coding` subclasses.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfSectionHeader32b`,
    :py:class:`ElfSectionHeader32l`, :py:class:`ElfSectionHeader64b`,
    and :py:class:`ElfSectionHeader64l`.  This base class sets useless
    defaults and includes any byte order and word size independent
    methods while the subclasses define byte order and word size
    dependent methods.
    """

    nameoffset = None
    """
    Offset into the `section header string table section
    <http://www.sco.com/developers/gabi/latest/ch4.strtab.html>`_ of
    the name of this section.
    """

    name = None
    """
    The name of this section.
    """

    type = None
    """
    Section type encoded with :py:class:`SHT`.
    """

    flags = None
    """
    Flags which define miscellaneous attributes.  These are bit flags
    which are or'd together.  The individual bit-flags are encoded
    using :py:class:`SHF`.
    """

    addr = None
    """
    The load address of this section if it will appear in memory during a running process.
    """

    offset = None
    """
    Byte offset from the start of the file to the beginning of the content of this section.
    """

    section_size = None
    """
    Size in bytes of the content of this section.
    """

    link = None
    """
    A section header table index.  It's meaning varies by context.
    """

    info = None
    """
    Extra information.  It's meaning varies by context.
    """

    addralign = None
    """
    Section alignment constraints.
    """

    entsize = None
    """
    If the section holds fixed sized entries then this is the size of each entry.
    """

    content = None
    """
    A memory block representing the contents of this section.
    """

    def unpack_from(self, block, offset=0):
        (self.nameoffset, self.type, self.flags, self.addr,
         self.offset, self.section_size, self.link, self.info,
         self.addralign, self.entsize) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        """
        .. note:: this is a special case.  *block* here must be the
            entire file or we won't know how to place our content.
        """
        self.coder.pack_into(block, offset,
                             self.nameoffset, self.type.value, self.flags, self.addr,
                             self.offset, self.section_size, self.link, self.info,
                             self.addralign, self.entsize)

        ## now TODO this is duplicated code.... also writing somewhere (...vma...)
        ##block[self.offset:self.offset + self.section_size] = self.content

        return self

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
                and self.nameoffset == other.nameoffset
                and self.type == other.type
                and self.flags == other.flags
                and self.addr == other.addr
                and self.offset == other.offset
                and self.section_size == other.section_size
                and self.link == other.link
                and self.info == other.info
                and self.addralign == other.addralign
                and self.entsize == other.entsize
                and self.content == other.content)

    def close_enough(self, other):
        return (isinstance(other, self.__class__)
                and self.nameoffset == other.nameoffset
                and self.type == other.type
                and self.flags == other.flags
                and self.addr == other.addr
                and self.section_size == other.section_size
                and self.link == other.link
                and self.info == other.info
                and self.addralign == other.addralign
                and self.entsize == other.entsize
                and self.content == other.content)

    def __repr__(self):
        # FIXME: I wish I could include the first few bytes of the content as well.
        return ('<{0}@{1}: name=\'{2}\', type={3},'
                ' flags={4}, addr={5}, offset={6}, section_size={7},'
                ' link={8}, info={9}, addralign={10}, entsize={11}>'
                .format(self.__class__.__name__, hex(id(self)), self.name,
                        SHT(self.type).name if self.type in list(SHT) else hex(self.type),
                        hex(self.flags), hex(self.addr), self.offset, self.section_size,
                        self.link, self.info, self.addralign, self.entsize))

    def _list_encode(self):
        return (self.__class__.__name__,
                hex(id(self)),
                {
                    'name': self.name,
                    'type': SHT.bycode[self.type].name if self.type in list(SHT) else self.type,
                    'flags': hex(self.flags),
                    'offset': self.offset,
                    'section_size': self.section_size,
                    'link': self.link,
                    'info': self.info,
                    'addralign': self.addralign,
                    'entsize': self.entsize,
                })


class ElfSectionHeader32b(ElfSectionHeader):
    """
    A subclass of :py:class:`ElfSectionHeader`.  This one represents
    32-bit, big-endian structs.
    """
    coder = struct.Struct(b'>IIIIIIIIII')


class ElfSectionHeader32l(ElfSectionHeader):
    """
    A subclass of :py:class:`ElfSectionHeader`.  This one represents
    32-bit, little-endian structs.
    """
    coder = struct.Struct(b'<IIIIIIIIII')


class ElfSectionHeader64b(ElfSectionHeader):
    """
    A subclass of :py:class:`ElfSectionHeader`.  This one represents
    64-bit, big-endian structs.
    """
    coder = struct.Struct(b'>IIQQQQIIQQ')


class ElfSectionHeader64l(ElfSectionHeader):
    """
    A subclass of :py:class:`ElfSectionHeader`.  This one represents
    64-bit, little-endian structs.
    """
    coder = struct.Struct(b'<IIQQQQIIQQ')


class SHN(Enum):
    """
    Encodes special section indices into the section header table.

    This is a subclass of :py:class:`coding.Coding`.
    """
    SHN_UNDEF = 0  # 'marks an undefined, missing, irrelevant, or'
    SHN_LORESERVE = 0xff00  # 'specifies the lower bound of the range'
    SHN_BEFORE = 0xff00  # 'Order section before all others (Solaris).')
    SHN_LOPROC = 0xff00  # '')
    SHN_AFTER = 0xff01  # 'Order section after all others (Solaris).')
    SHN_HIPROC = 0xff1f  # '')
    SHN_LOOS = 0xff20  # '')
    SHN_HIOS = 0xff3f  # '')
    SHN_ABS = 0xfff1  # 'specifies absolute values for the corresponding'
    SHN_COMMON = 0xfff2  # 'symbols defined relative to this section are'
    SHN_XINDEX = 0xffff  # 'This value is an escape value. It indicates'
    SHN_HIRESERVE = 0xffff  # 'specifies the upper bound of the range of'


class SHT(IntEnum):
    """
    Encodes the type of a section as represented in the section header
    entry of `the section header table
    <http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.

    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfSectionHeader.type`.
    """
    SHT_NULL = 0  # 'marks the section header as inactive; it does not have an'
    SHT_PROGBITS = 1  # 'The section holds information defined by the program,'
    SHT_SYMTAB = 2  # 'provides symbols for link editing, though it may also'
    SHT_STRTAB = 3  # 'section holds a string table. An object file may have'
    SHT_RELA = 4  # 'section holds relocation entries with explicit addends,'
    SHT_HASH = 5  # 'section holds a symbol hash table')
    SHT_DYNAMIC = 6  # 'section holds information for dynamic linking')
    SHT_NOTE = 7  # 'section holds information that marks the file in some way')
    SHT_NOBITS = 8  # 'A section of this type occupies no space in the file'
    SHT_REL = 9  # 'section holds relocation entries without explicit addends')
    SHT_SHLIB = 10  # 'section type is reserved but has unspecified semantics')
    SHT_DYNSYM = 11  # 'holds a minimal set of dynamic linking symbols,')
    SHT_INIT_ARRAY = 14  # 'section contains an array of pointers to initialization functions')
    SHT_FINI_ARRAY = 15  # 'section contains an array of pointers to termination functions')
    SHT_PREINIT_ARRAY = 16  # 'section contains an array of pointers to functions'
    SHT_GROUP = 17  # 'section defines a section group')
    SHT_SYMTAB_SHNDX = 18  # 'section is associated with a section of type'
    SHT_LOOS = 0x60000000  # '')
    SHT_GNU_ATTRIBUTES = 0x6ffffff5  # 'Object attributes.')
    SHT_GNU_HASH = 0x6ffffff6  # 'GNU-style hash table.')
    SHT_GNU_LIBLIST = 0x6ffffff7  # 'Prelink library lis')
    SHT_CHECKSUM = 0x6ffffff8  # 'Checksum for DSO content.')
    SHT_LOSUNW = 0x6ffffffa  # 'Sun-specific low bound.')
    SHT_SUNW_move = 0x6ffffffa  # 'efine SHT_SUNW_COMDAT')
    SHT_SUNW_COMDAT = 0x6ffffffb  # '')
    SHT_SUNW_syminfo = 0x6ffffffc  # '')
    SHT_GNU_verdef = 0x6ffffffd  # 'Version definition section.')
    SHT_GNU_verneed = 0x6ffffffe  # 'Version needs section.')
    SHT_GNU_versym = 0x6fffffff  # 'Version symbol table.')
    SHT_HISUNW = 0x6fffffff  # 'Sun-specific high bound.')
    SHT_HIOS = 0x6fffffff  # '')
    SHT_LOPROC = 0x70000000  # '')
    SHT_HIPROC = 0x7fffffff  # '')
    SHT_LOUSER = 0x80000000  # '')
    SHT_HIUSER = 0xffffffff  # '')


class SHF():
    """
    Encodes the section flags as represented in the section header
    entry of `the section header table
    <http://www.sco.com/developers/gabi/latest/ch4.sheader.html#section_header>`_.

    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfSectionHeader.flags`.  These are bit flags which are
    or'd together.
    """
    SHF_WRITE = 0x1  # 'section contains data that should be writable'
    SHF_ALLOC = 0x2  # 'section occupies memory during process execution')
    SHF_EXECINSTR = 0x4  # 'section contains executable machine instructions')
    SHF_MERGE = 0x10  # 'data in the section may be merged to eliminate'
    SHF_STRINGS = 0x20  # 'data elements in the section consist of'
    SHF_INFO_LINK = 0x40  # 'The sh_info field of this section header'
    SHF_LINK_ORDER = 0x80  # 'adds special ordering requirements for link editors')
    SHF_OS_NONCONFORMING = 0x100  # 'section requires special OS-specific processing')
    SHF_GROUP = 0x200  # 'section is a member of a section group')
    SHF_TLS = 0x400  # 'section holds Thread-Local Storage')
    SHF_MASKOS = 0x0ff00000  # 'All bits included in this mask are reserved'
    SHF_MASKPROC = 0xf0000000  # 'All bits included in this mask are reserved'
    SHF_ORDERED = (1 << 30)  # , 'Special ordering requirement (Solaris).')
    SHF_EXCLUDE = (1 << 31)  # , 'Section is excluded unless referenced or allocated (Solaris).')


# copied from pyelftools (TODO)
def roundup(num, bits):
    """ Round up a number to nearest multiple of 2^bits. The result is a number
        where the least significant bits passed in bits are 0.
    """
    return (num - 1 | (1 << bits) - 1) + 1


class ElfNotes:
    notes = []
    coder = struct.Struct("<III")

    # We can append either a single note, or a list of notes.
    def append(self, note):
        if isinstance(note, list):
            self.notes.extend(note)
        else:
            self.notes.append(note)

    def pack_into(self, block, offset=0):
        # notes header: namesz(word), descsz(word), ntype(word)?
        # hmm. there are 20 bytes of header as far as I can see
        # 0x05 (size of name "CORE"?), 0x88 (size of header), 0x03 (type PSINFO), CORE\0+padding
        # round namesz up (4 byte aligned)
        for n in self.notes:
            # Notes header: name length, descriptor length, type of note
            self.coder.pack_into(block, offset, len(n.NOTE_NAME) + 1, n.size, n.NOTE_TYPE)
            offset += 12
            block[offset:offset + len(n.NOTE_NAME) + 1] = n.NOTE_NAME + b'\0'
            # block[offset+len(n.NOTE_NAME):offset+len(n.NOTE_NAME)+1] = b'\0'
            offset += roundup(len(n.NOTE_NAME) + 1, 2)
            n.pack_into(block, offset)
            offset += n.size

    class _Size(object):
        def __get__(self, obj, t):
            sz = 0
            for n in t.notes:
                sz += t.coder.size + roundup(len(n.NOTE_NAME) + 1, 2) + n.size
            return sz

    size = _Size()


class ElfNotePRPSINFO(StructBase):
    pr_state = 0
    pr_sname = b'R'
    pr_zomb = 0
    pr_nice = 0
    pr_flag = 0
    pr_uid = 11
    pr_gid = 12
    pr_pid = 13
    pr_ppid = 14
    pr_pgrp = 15
    pr_sid = 16
    pr_fname = b'none'
    pr_psargs = b'none'

    # NOTE_NAME = b'NT_PRPSINFO'
    NOTE_NAME = b'CORE'
    NOTE_TYPE = 3

    # TODO: flags (5th arg) are 64bitt/32bit depending on arch? plus padding
    # kernel_uid is 32bit? uid_t as well
    coder = struct.Struct("<bcbbxxxxQiiiiii16s80s")

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset, self.pr_state, self.pr_sname,
                             self.pr_zomb, self.pr_nice, self.pr_flag,
                             self.pr_uid, self.pr_gid, self.pr_pid, self.pr_ppid, self.pr_pgrp, self.pr_sid,
                             self.pr_fname, self.pr_psargs)
        return self


class ElfNotePRStatusRegSet(StructBase):
    registers = dict()
    fields = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
              "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp",
              "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]
    coder = struct.Struct("<Q")

    class _Size(object):
        def __get__(self, obj, t):
            return len(t.fields) * 8

    size = _Size()

    def pack_into(self, block, offset):
        logger.debug("PRstatusRegSet: Registers: %s", str(self.registers))
        for i in self.fields:
            self.coder.pack_into(block, offset, self.registers.get(i, 0))
            offset += self.coder.size
        return self



class ElfNotePRSTATUS(StructBase):
    def __init__(self):
        self.registers = ElfNotePRStatusRegSet()  # ordered dictionary of register to value mappings

    registers = ElfNotePRStatusRegSet()  # needed for size...
    info = {"si_signo": 0, "si_code": 0, "si_errno": 0}
    cursig = 0  # 16bit => "h", I assume followed by padding to make it 32bit aligned
    sigpend = 0  # ulong => "Q"
    sighold = 0  # uling => "Q"
    pid = 0
    ppid = 0
    pgrp = 0
    sid = 0
    utime = {"tv_sec": 0, "tv_usec": 0}
    stime = {"tv_sec": 0, "tv_usec": 0}
    cutime = {"tv_sec": 0, "tv_usec": 0}
    cstime = {"tv_sec": 0, "tv_usec": 0}
    fpvalid = 0
    NOTE_NAME = b'CORE'  # b'NT_PRSTATUS'
    NOTE_TYPE = 1

    coder = struct.Struct("<12shxxQQiiii16s16s16s16s")
    fpcoder = struct.Struct("<Ixxxx")
    sigcoder = struct.Struct("<iii")
    tvcoder = struct.Struct("<qq")

    def packsig(self, info):
        # errno / code order needs to be check (depend on __ARCH_HAS_SWAPPED_SIGINFO)
        # SI_MAX_SIZE is actually 128?? That would quite be a lot....
        # BUt that would be in a different header
        # elf_siginfo is just three ints.
        return self.sigcoder.pack(info["si_signo"], info["si_errno"], info["si_code"])

    def packtv(self, tv):
        return self.tvcoder.pack(tv["tv_sec"], tv["tv_usec"])

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset,
                             self.packsig(self.info),  # signal info
                             self.cursig,
                             self.sigpend,
                             self.sighold,
                             self.pid, self.ppid, self.pgrp, self.sid,
                             self.packtv(self.utime), self.packtv(self.stime),
                             self.packtv(self.cutime), self.packtv(self.cstime))
        # append registers
        sz = self.coder.size
        logger.debug("Packing registers into status note at relative offset %x", sz)
        self.registers.pack_into(block=block, offset=offset + self.coder.size)
        # append fpvalid
        self.fpcoder.pack_into(block, offset + self.coder.size + self.registers.__sizeof__(), 0)
        return self

    class _Size(object):
        def __get__(self, obj, t):
            return t.coder.size + t.registers.size + t.fpcoder.size

    size = _Size()


class ElfNoteAUXV(StructBase):
    NOTE_NAME = b'CORE'
    NOTE_TYPE = 6  # 6 = NT_AUXV
    coder = struct.Struct("<Q")
    auxv = []

    # auxv is task.mm.saved_auxv
    def __init__(self, auxv):
        logger.debug("AUXV init with %d elements", len(auxv))
        self.auxv = auxv

    def pack_into(self, block, offset):
        # it = iter(auxv)
        # for aux in zip(it,it):
        for aux in self.auxv:
            self.coder.pack_into(block, offset, aux)
            offset += self.coder.size
        return self

    class _Size(object):
        def __get__(self, obj, t):
            logger.debug("getting auxv size: %d", (t.coder.size * len(obj.auxv)))
            return t.coder.size * len(obj.auxv)

    size = _Size()


class ElfProgramHeader(StructBase):
    """
    This abstract base class corresponds to a `program header
    <http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.
    
    Most attributes are :py:class:`int`'s.  Some have encoded meanings
    which can be decoded with the accompanying
    :py:class:`coding.Coding` subclasses.

    This abstract base class works in tight concert with it's
    subclasses: :py:class:`ElfProgramHeader32b`,
    :py:class:`ElfProgramHeader32l`, :py:class:`ElfProgramHeader64b`,
    and :py:class:`ElfProgramHeader64l`.  This base class sets useless
    defaults and includes any byte order and word size independent
    methods while the subclasses define byte order and word size
    dependent methods.
    """

    PN_XNUM = 0xffff
    """
    Program header overflow number.
    """

    type = None
    """
    Segment type encoded with :py:class:`PT`.
    """

    offset = None
    """
    Offset in bytes from the beginning of the file to the start of this segment.
    """

    vaddr = None
    """
    Virtual address at which this segment will reside in memory when loaded to run.
    """

    paddr = None
    """
    Physical address in memory, when physical addresses are used.
    """

    filesz = None
    """
    Segment size in bytes in file.
    """

    memsz = None
    """
    Segment size in bytes when loaded into memory.  Must be at least
    :py:attr:`ElfProgramHeader.filesz` or greater.  Extra space is
    zero'd out.
    """

    flags = None
    """
    Flags for the segment.  Encoded using :py:class:`PF`.
    """

    content = None
    """
    A memory block representing the contents of this section.
    """

    align = None
    """
    Alignment of both segments in memory as well as in file.
    """

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
                and self.type == other.type
                and self.offset == other.offset
                and self.vaddr == other.vaddr
                and self.paddr == other.paddr
                and self.filesz == other.filesz
                and self.memsz == other.memsz
                and self.flags == other.flags
                and self.align == other.align)

    def __repr__(self):
        return ('<{0}@{1}: type={2},'
                ' offset={3}, vaddr={4}, paddr={5},'
                ' filesz={6}, memsz={7}, flags={8}, align={9}>'
                .format(self.__class__.__name__, hex(id(self)),
                        PT(self.type).name if self.type in list(PT) else self.type,
                        self.offset, hex(self.vaddr), hex(self.paddr),
                        self.filesz, self.memsz, hex(self.flags), self.align))

    def _list_encode(self):
        return (self.__class__.__name__,
                hex(id(self)),
                {
                    'type': PT(self.type).name if self.type in list(PT) else self.type,
                    'offset': self.offset,
                    'vaddr': hex(self.vaddr),
                    'paddr': hex(self.paddr),
                    'filesz': self.filesz,
                    'memsz': self.memsz,
                    'flags': hex(self.flags),
                    'align': self.align,
                })


class PT(IntEnum):
    """
    Encodes the segment type as recorded in the `program header
    <http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.

    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfProgramHeader.type`.
    """
    PT_NULL = 0  # 'array element is unused')
    PT_LOAD = 1  # 'array element specifies a loadable segment')
    PT_DYNAMIC = 2  # 'array element specifies dynamic linking information')
    PT_INTERP = 3  # 'array element specifies the location and size'
    PT_NOTE = 4  # 'array element specifies the location and size of'
    PT_SHLIB = 5  # 'segment type is reserved')
    PT_PHDR = 6  # 'specifies the location and size of the program'
    PT_TLS = 7  # 'array element specifies the Thread-Local Storage template')
    PT_LOOS = 0x60000000  # '')
    PT_GNU_EH_FRAME = 0x6474e550  # 'GCC .eh_frame_hdr segment')
    PT_GNU_STACK = 0x6474e551  # 'Indicates stack executability')
    PT_GNU_RELRO = 0x6474e552  # 'Read only after relocation')
    PT_LOSUNW = 0x6ffffffa  # '')
    PT_SUNWBSS = 0x6ffffffa  # 'Sun Specific segment')
    PT_SUNWSTACK = 0x6ffffffb  # 'Stack segment')
    PT_HISUNW = 0x6fffffff  # '')
    PT_HIOS = 0x6fffffff  # '')
    PT_LOPROC = 0x70000000  # '')
    PT_HIPROC = 0x7fffffff  # '')


class PF():
    """
    Encodes the segment flags as recorded in the `program header
    <http://www.sco.com/developers/gabi/latest/ch5.pheader.html>`_.

    This is a subclass of :py:class:`coding.Coding` and encodes
    :py:attr:`ElfProgramHeader.flags`.
    """
    PF_X = 0x1  # 'Execute')
    PF_W = 0x2  # 'Write')
    PF_R = 0x4  # 'Read')
    PF_MASKOS = 0x0ff00000  # 'Unspecified')
    PF_MASKPROC = 0xf0000000  # 'Unspecified')


class ElfProgramHeader32(ElfProgramHeader):
    """
    32 vs 64 bit files have differing element orders.  This class
    represents the 32 bit element order.  A subclass of
    :py:class:`ElfProgramHeader`.
    """

    def unpack_from(self, block, offset=0):
        (self.type, self.offset, self.vaddr, self.paddr,
         self.filesz, self.memsz, self.flags, self.align) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        self.coder.pack_into(block, offset,
                             self.type, self.offset, self.vaddr, self.paddr,
                             self.filesz, self.memsz, self.flags, self.align)

        return self


class ElfProgramHeader64(ElfProgramHeader):
    """
    32 vs 64 bit files have differing element orders.  This class
    represents the 64 bit element order.  A subclass of
    :py:class:`ElfProgramHeader`.
    """

    def unpack_from(self, block, offset=0):
        (self.type, self.flags, self.offset, self.vaddr,
         self.paddr, self.filesz, self.memsz, self.align) = self.coder.unpack_from(block, offset)

        return self

    def pack_into(self, block, offset=0):
        logger.debug("ELF Program Header: %s", str(self))
        self.coder.pack_into(block, offset,
                             self.type.value, self.flags, self.offset, self.vaddr,
                             self.paddr, self.filesz, self.memsz, self.align)

        return self


class ElfProgramHeader32b(ElfProgramHeader32):
    """
    A subclass of :py:class:`ElfProgramHeader32`.  Represents big
    endian byte order.
    """
    coder = struct.Struct(b'>IIIIIIII')


class ElfProgramHeader32l(ElfProgramHeader32):
    """
    A subclass of :py:class:`ElfProgramHeader32`.  Represents little
    endian byte order.
    """
    coder = struct.Struct(b'<IIIIIIII')


class ElfProgramHeader64b(ElfProgramHeader64):
    """
    A subclass of :py:class:`ElfProgramHeader64`.  Represents big
    endian byte order.
    """
    coder = struct.Struct(b'>IIQQQQQQ')


class ElfProgramHeader64l(ElfProgramHeader64):
    """
    A subclass of :py:class:`ElfProgramHeader64`.  Represents little
    endian byte order.
    """
    coder = struct.Struct(b'<IIQQQQQQ')


class ElfFile32b(ElfFile):
    """
    A subclass of :py:class:`ElfFile`.  Represents 32-bit, big-endian
    files.
    """
    fileHeaderClass = ElfFileHeader32b
    sectionHeaderClass = ElfSectionHeader32b
    programHeaderClass = ElfProgramHeader32b


class ElfFile32l(ElfFile):
    """
    A subclass of :py:class:`ElfFile`.  Represents 32-bit,
    little-endian files.
    """
    fileHeaderClass = ElfFileHeader32l
    sectionHeaderClass = ElfSectionHeader32l
    programHeaderClass = ElfProgramHeader32l


class ElfFile64b(ElfFile):
    """
    A subclass of :py:class:`ElfFile`.  Represents 64-bit, big-endian
    files.
    """
    fileHeaderClass = ElfFileHeader64b
    sectionHeaderClass = ElfSectionHeader64b
    programHeaderClass = ElfProgramHeader64b


class ElfFile64l(ElfFile):
    """
    A subclass of :py:class:`ElfFile`.  Represents 64-bit,
    little-endian files.
    """
    fileHeaderClass = ElfFileHeader64l
    sectionHeaderClass = ElfSectionHeader64l
    programHeaderClass = ElfProgramHeader64l


_fileEncodingDict = {
    1: {
        1: ElfFile32l,
        2: ElfFile32b,
    },
    2: {
        1: ElfFile64l,
        2: ElfFile32b,
    },
}
"""
This is a dict of dicts.  The first level keys correspond to
:py:class:`ElfClass` codes and the values are second level dicts.  The
second level dict keys correspond to :py:class:`ElfData` codes and the
second level values are the four :py:class:`ElfFile` subclasses.  It
is used by :py:meth:`ElfClass.encodedClass` to determine an
appropriate subclass to represent a file based on a
:py:class:`ElfFileIdent`.
"""


class GRP(Enum):
    GRP_COMDAT = 0x1  # 'This is a COMDAT group')
    GRP_MASKOS = 0x0ff00000  # 'All bits included in this mask are'' reserved for operating system-specific semantics')
    GRP_MASKPROC = 0xf0000000  # 'All bits included in this mask'' are reserved for processor-specific semantics')
