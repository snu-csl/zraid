#ifndef __ZRWA_H__
#define __ZRWA_H__

#include <linux/nvme_ioctl.h>
#include <linux/blkdev.h>


enum nvme_zns_send_action {
	NVME_ZNS_ZSA_CLOSE		= 0x1,
	NVME_ZNS_ZSA_FINISH		= 0x2,
	NVME_ZNS_ZSA_OPEN		= 0x3,
	NVME_ZNS_ZSA_RESET		= 0x4,
	NVME_ZNS_ZSA_OFFLINE		= 0x5,
	NVME_ZNS_ZSA_SET_DESC_EXT	= 0x10,
	NVME_ZNS_ZSA_ZRWA_FLUSH		= 0x11,
};


#define NVME_ZNS_MGMT_SEND_ZSASO_SHIFT 9
#define	NVME_ZNS_MGMT_SEND_ZSASO_MASK 0x1
#define	NVME_ZNS_MGMT_SEND_SEL_SHIFT 8
#define	NVME_ZNS_MGMT_SEND_SEL_MASK	0x1
#define NVME_ZNS_MGMT_SEND_ZSA_SHIFT 0
#define NVME_ZNS_MGMT_SEND_ZSA_MASK 0xff

#define NVME_SET(value, name) \
        (((value) & NVME_##name##_MASK) << NVME_##name##_SHIFT)


struct nvme_passthru_cmd* create_pt(int opcode, int nsid, __u64 buf, size_t data_len, int cdw2, int cdw3, int cdw10, int cdw11, int cdw12);
struct nvme_passthru_cmd* nvm_write(size_t data_len, char *host_buf, __u64 lba);
struct nvme_passthru_cmd* nvm_read(size_t data_len, char *host_buf, __u64 lba);
struct nvme_passthru_cmd* zrwa_flush_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, __u32 timeout);
struct nvme_passthru_cmd* open_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int zrwaa, int select_all, __u32 timeout); 
struct nvme_passthru_cmd* finish_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int select_all, __u32 timeout); 
struct nvme_passthru_cmd* reset_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int select_all, __u32 timeout); 
struct nvme_passthru_cmd* close_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int zrwaa, int select_all, __u32 timeout);
int nvme_submit_passthru_cmd_sync(struct block_device *bdev,
                                  struct nvme_passthru_cmd *cmd);


#endif //ifdef __ZRWA_H__