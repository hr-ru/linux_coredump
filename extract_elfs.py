import io
from typing import List


from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

from volatility3.plugins.linux import pslist

class ExtractElfs(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ListRequirement(name='pid',
                                         description='Filter on specific process IDs',
                                         element_type=int,
                                         optional=True),
            requirements.StringRequirement(name='elf-file', description='ELF file', optional=False),
            requirements.StringRequirement(name='output-file', description='Output file', optional=False)
        ]

    def _generator(self, tasks):
        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            name = utility.array_to_string(task.comm)

            for vma in task.mm.get_mmap_iter():
                hdr = proc_layer.read(vma.vm_start, 4, pad = True)
                if not (hdr[0] == 0x7f and hdr[1] == 0x45 and hdr[2] == 0x4c and hdr[3] == 0x46):
                    continue

                path = vma.get_name(self.context, task)

                if path == self.config['elf-file']:
                    with io.FileIO(self.config['output-file'], "wb+") as f:
                        proc_layer_name = task.add_process_layer()

                        proc_layer = self.context.layers[proc_layer_name]

                        f.write(proc_layer.read(vma.vm_start, vma.vm_end - vma.vm_start, pad=True))

                    yield (0, (task.pid, name, format_hints.Hex(vma.vm_start), format_hints.Hex(vma.vm_end), path))
                    return

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Start", format_hints.Hex),
                                   ("End", format_hints.Hex), ("File Path", str)],
                                  self._generator(
                                      pslist.PsList.list_tasks(self.context,
                                                               self.config['kernel'],
                                                               filter_func=filter_func)))
