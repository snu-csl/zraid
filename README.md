# ZRAID

## Introduction

ZRAID is a software RAID driver for ZNS SSDs. It is implemented as a Linux kernel module providing the system with an abstraction of unified ZNS-interface SSD.

Further details on the design and implementation of ZRAID can be found in the following papers.
- [ZRAID: Leveraging Zone Random Write Area (ZRWA) for Alleviating Partial Parity Tax in ZNS RAID (ASPLOS 2025)]


## Installation

### Hardware requirement
ZRAID requires five identical ZN540 devices. Other configurations have not been tested and cannot be guaranteed to operate correctly.

### Linux kernel requirement
The supported Linux kernel version is v5.15.0 with supplied patch in this repository.

### Compiling NVMe driver
ZRAID depends on direct submission of specific ZRWA-related commands that does not natively supported by NVMe driver. Modified nvme driver in this repository should be compiled before the compilation of ZRAID.

Compile and insert the modified NVMe driver:
```
$ cd nvme
$ bash make.sh
# insmod nvme-core.ko
# insmod nvme.ko
```

### Configuring `ZRAID`

```
$ git clone https://github.com/snu-csl/zraid
$ cd src
$ make CFLAGS=-DPP_INPLACE
# insmod zraid.ko
# echo "0 [logical_array_space_in_sector] zraid [chunk_size_kb] 16 1 0 [device_string]" | sudo dmsetup create [array_name]
```

##### Examples
- 5 x 1TB ZN540(899 data zones) array: 2GiB(zone size) * 899 * 4 = 15082717184 sectors
- device_string: `/dev/nvme0n2 /dev/nvme1n2 /dev/nvme2n2 /dev/nvme3n2 /dev/nvme4n2`

### Scripts

- `init_zraid.sh` — Compile and insert the modified NVMe driver
- `run_zraid.sh` — Reset devices & Configure ZRAID
- `reset.sh` — Reset devices
- `setup_samsung.sh` — Set dm_linear devices for PM1731a
- `unset_samsung.sh` — Unset dm_linear devices for PM1731a
- `ctest-run_zraid.sh` — Recovery test script after a crash

##### ZRAID initialization example
```bash
bash init_zraid.sh
bash run_zraid.sh wd # For ZN540 devices
```


### License
ZRAID is offered under the terms of the GNU General Public License version 2 as published by the Free Software Foundation. More information about this license can be found [here](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
