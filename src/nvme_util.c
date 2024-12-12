#include "nvme_util.h"

struct nvme_passthru_cmd* create_pt(int opcode, int nsid, __u64 buf, size_t data_len, int cdw2, int cdw3, int cdw10, int cdw11, int cdw12)
{
    struct nvme_passthru_cmd *pt = NULL;

    pt = (struct nvme_passthru_cmd *)kmalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);
    if (pt == NULL) {
       printk("Failed to allocate memory for passthru structure\n");
       return -1;
    }

    pt->opcode = opcode;
    pt->nsid = nsid;
    pt->addr = buf;
    pt->data_len = data_len;
    pt->cdw2 = cdw2;
    pt->cdw3 = cdw3;
    pt->cdw10 = cdw10;
    pt->cdw11 = cdw11;
    pt->cdw12 = cdw12;

    return pt;
}

struct nvme_passthru_cmd* nvm_write(size_t data_len, char *host_buf, __u64 lba)
{
    return create_pt(0x1, 1, (__u64) host_buf, data_len, 0, 0, lba & 0xFFFFFFFF, lba >> 32, data_len / 512 - 1);
}

struct nvme_passthru_cmd* nvm_read(size_t data_len, char *host_buf, __u64 lba)
{
    return create_pt(0x2, 1, (__u64) host_buf, data_len, 0, 0, lba & 0xFFFFFFFF, lba >> 32, data_len / 512 - 1);
}

struct nvme_passthru_cmd* zrwa_flush_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, __u32 timeout)
{
    char *data;

    cmd->opcode = 0x79;
    cmd->nsid = ns_id;
    cmd->cdw10 = lba & 0xFFFFFFFF;
    cmd->cdw11 = lba >> 32;
    cmd->cdw13 = NVME_SET(0, ZNS_MGMT_SEND_ZSASO) |
			NVME_SET(!!0, ZNS_MGMT_SEND_SEL) |
			NVME_SET(NVME_ZNS_ZSA_ZRWA_FLUSH, ZNS_MGMT_SEND_ZSA);
    //pt->cdw13 =  NVME_SET(NVME_ZNS_ZSA_ZRWA_FLUSH, ZNS_MGMT_SEND_ZSA);

    data = NULL;
    cmd->addr = (__u64)data;
    cmd->data_len = 0;
    cmd->timeout_ms = timeout;

    return cmd;
}

// void open_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int zrwaa, int select_all, __u32 timeout) 
struct nvme_passthru_cmd* open_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int zrwaa, int select_all, __u32 timeout) 
{
    // struct nvme_passthru_cmd *cmd = NULL;
    // cmd = (struct nvme_passthru_cmd*)kmalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);

    cmd->opcode = 0x79;
    cmd->nsid = ns_id;
    cmd->cdw10 = lba & 0xFFFFFFFF;
    cmd->cdw11 = lba >> 32;
    cmd->cdw13 =  NVME_SET(zrwaa, ZNS_MGMT_SEND_ZSASO) |
                    NVME_SET(!!select_all, ZNS_MGMT_SEND_SEL) |
                    NVME_SET(NVME_ZNS_ZSA_OPEN, ZNS_MGMT_SEND_ZSA);

    cmd->addr = 0;
    cmd->data_len = 0;
    cmd->timeout_ms = timeout;

    return cmd;
}

// void open_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int select_all, __u32 timeout) 
struct nvme_passthru_cmd* close_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int zrwaa, int select_all, __u32 timeout) 
{
    // struct nvme_passthru_cmd *cmd = NULL;
    // cmd = (struct nvme_passthru_cmd*)kmalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);

    cmd->opcode = 0x79;
    cmd->nsid = ns_id;
    cmd->cdw10 = lba & 0xFFFFFFFF;
    cmd->cdw11 = lba >> 32;
    cmd->cdw13 =  NVME_SET(zrwaa, ZNS_MGMT_SEND_ZSASO) |
                    NVME_SET(!!select_all, ZNS_MGMT_SEND_SEL) |
                    NVME_SET(NVME_ZNS_ZSA_CLOSE, ZNS_MGMT_SEND_ZSA);

    cmd->addr = 0;
    cmd->data_len = 0;
    cmd->timeout_ms = timeout;

    return cmd;
}


// void open_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id, int select_all, __u32 timeout) 
struct nvme_passthru_cmd* reset_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id,  int select_all, __u32 timeout) 
{
    // struct nvme_passthru_cmd *cmd = NULL;
    // cmd = (struct nvme_passthru_cmd*)kmalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);

    cmd->opcode = 0x79;
    cmd->nsid = ns_id;
    cmd->cdw10 = lba & 0xFFFFFFFF;
    cmd->cdw11 = lba >> 32;
    cmd->cdw13 =  NVME_SET(0, ZNS_MGMT_SEND_ZSASO) |
                    NVME_SET(!!select_all, ZNS_MGMT_SEND_SEL) |
                    NVME_SET(NVME_ZNS_ZSA_RESET, ZNS_MGMT_SEND_ZSA);

    cmd->addr = 0;
    cmd->data_len = 0;
    cmd->timeout_ms = timeout;

    return cmd;
}

// void open_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id,  int select_all, __u32 timeout) 
struct nvme_passthru_cmd* finish_zone(struct nvme_passthru_cmd *cmd, __u64 lba, __u32 ns_id,  int select_all, __u32 timeout) 
{
    // struct nvme_passthru_cmd *cmd = NULL;
    // cmd = (struct nvme_passthru_cmd*)kmalloc(sizeof(struct nvme_passthru_cmd), GFP_KERNEL);

    cmd->opcode = 0x79;
    cmd->nsid = ns_id;
    cmd->cdw10 = lba & 0xFFFFFFFF;
    cmd->cdw11 = lba >> 32;
    cmd->cdw13 =  NVME_SET(0, ZNS_MGMT_SEND_ZSASO) |
                    NVME_SET(!!select_all, ZNS_MGMT_SEND_SEL) |
                    NVME_SET(NVME_ZNS_ZSA_FINISH, ZNS_MGMT_SEND_ZSA);

    cmd->addr = 0;
    cmd->data_len = 0;
    cmd->timeout_ms = timeout;

    return cmd;
}
