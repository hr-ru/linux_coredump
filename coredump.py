# File originally by Jonas Pöhler
#
# Note:
# There is code based on the following:
# based on work from https://github.com/Angelomirabella/linux_coredump/blob/master/coredump.py
# (no license statement)
# based on work from https://github.com/checkpoint-restore/criu/tree/criu-dev/coredump
# (GPL licensed)
# but that code is not in this file (coredump.py), but in dump.py.

import io
import logging
import struct
from typing import List

from . import dump

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import StructType

from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


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
            requirements.StringRequirement(name='output-file', description='Output file', optional=False)
        ]



    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])
        task_list = list(pslist.PsList.list_tasks(context=self.context,
                                                  vmlinux_module_name=self.config['kernel'],
                                                  filter_func=filter_func))
        assert len(task_list) == 1

        # Get registers from main thread of task
        task: StructType = task_list[0]


        kernel = self.config['kernel']
        cd = dump.coredump(self.context, task, kernel, dump.coredump.ELF_ISA_x86_64)
        cd.generate_coredump()
        with io.FileIO(self.config['output-file'], "wb+") as f:
            cd.write(f)

        return renderers.TreeGrid([("Virtual", str)], [])
