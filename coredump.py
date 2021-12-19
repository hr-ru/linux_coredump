import collections
import io
import logging
import os
import struct
from typing import List

from volatility3.plugins.linux import dump

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import StructType

from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

offsets = {
    "32bit": [
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
    ],
    "64bit": [
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
        'unknown',  # I'm not sure what this field is
        'rip',
        'cs',
        'eflags',
        'rsp',
        'ss'
    ]
}

reg_size = {
    "32bit": 0x4,
    "64bit": 0x8
}

fmt = {
    "32bit": "<I",
    "64bit": "<Q"
}


class Coredump(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.IntRequirement(name='pid',
                                        description="Process ID to include (all other processes are excluded)",
                                        optional=False),
            requirements.StringRequirement(name='dump-dir', description='Output directory', optional=False),
            requirements.StringRequirement(name='output-file', description='Output file', optional=False)
        ]

    def _parse_kernel_stack(self, task):
        result = collections.OrderedDict()
        vmlinux = self.context.modules[self.config['kernel']]
        if hasattr(task, "sp"):
            sp = task.sp
            # proc_as = task.get_process_address_space()
            addr = sp

            for reg in offsets["64bit"][::-1]:  # reverse list, because we read up in the stack
                # debug.info("Reading {:016x}".format(addr))
                # 64-bit only
                addr -= 0x8
                val_raw = self.context.layers.read(vmlinux.layer_name, addr, 0x8)
                val = struct.unpack('<Q', val_raw)[0]
                result[reg] = val
            return result
        return None

    def run(self):

        self.config['output-file'] = os.path.join(self.config['dump-dir'], self.config['output-file'])

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])
        task_list = list(pslist.PsList.list_tasks(context=self.context,
                                                  vmlinux_module_name=self.config['kernel'],
                                                  filter_func=filter_func))
        assert len(task_list) == 1
        task: StructType = task_list[0]

        vmas = task.mm.get_mmap_iter()

        thread_registers = {}

        thread_task = task.thread
        regs = self._parse_kernel_stack(thread_task)
        thread_registers[task.pid] = regs

        for t in task.thread_group:
            regs = self._parse_kernel_stack(t.thread)
            if regs:
                thread_registers[t.pid] = regs

        cd = dump.coredump(self.context, task, vmas, thread_registers, False)
        cd.generate_coredump()
        with io.FileIO(self.config['output-file'], "wb+") as f:
            cd.write(f)

        return renderers.TreeGrid([("Virtual", str)], [])
