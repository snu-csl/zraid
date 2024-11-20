# ZRAID

## Introduction

ZRAID is a software RAID driver for ZNS SSDs. It is implemented as a Linux kernel module providing the system with an abstraction of unified ZNS-interface SSD.

Further details on the design and implementation of NVMeVirt can be found in the following papers.
- [ZRAID: Leveraging Zone Random Write Area (ZRWA) for Alleviating Partial Parity Tax in ZNS RAID (ASPLOS 2025)]


## Installation

### Linux kernel requirement
The supported Linux kernel version is v5.15.0 with supplied patch in this repository.

### Compiling NVMe driver
ZRAID depends on direct submission of specific ZRWA-related commands that does not natively supported by NVMe driver. Modified nvme driver in this repository should be compiled before the compilation of ZRAID.

Compile the modified NVMe driver:
```
cd nvme
bash make.sh
```

### Kernel boot parameters
To optimize performance, kernel boot parameters can be modified in `/etc/default/grub`. On our test machine, the `GRUB_CMDLINE_LINUX` parameters listed below are already set. You only need to comment/uncomment the relevant lines as required. Please avoid altering any other parameters, as improper modifications may cause the system to fail to boot.

For experiments on a native machine (Figures 7-11, claims):
`GRUB_CMDLINE_LINUX="quite splash intel_pstate=disable intel_iommu=off intel_idle.max_cstate=0" # ASPLOS submit`       

For experiments on QEMU (Table 1) with IOMMU enabled:
`GRUB_CMDLINE_LINUX="quite splash intel_pstate=disable intel_iommu=on iommu=pt processor.max_cstate=1 intel_idle.max_cstate=0 numa_balancing=disable irqbalance=0" #qemu`                                                

To apply these modifications, a reboot is required:
```
sudo update-grub
sudo reboot
```

### Compiling `ZRAID`
Please download the latest version of `ZRAID` from Github:

```bash
$ git clone https://github.com/snu-csl/zraid
```



## License
ZRAID is offered under the terms of the GNU General Public License version 2 as published by the Free Software Foundation. More information about this license can be found [here](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
