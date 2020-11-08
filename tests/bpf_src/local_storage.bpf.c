#include "pybpf.bpf.h" /* Auto generated helpers */
#include "vmlinux.h"

BPF_ARRAY(test_array, int, 1, 0);
BPF_INODE_STORAGE(inode_storage, int, 0);

SEC("lsm/inode_create")
int BPF_PROG(do_create, struct inode *dir, struct dentry *dentry)
{
    int *storage;

    storage = bpf_inode_storage_get(&inode_storage, dentry->d_inode, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);

    if (!storage)
        return 0;

    *storage = 12;

    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(do_unlink, struct inode *dir, struct dentry *dentry)
{
    int zero = 0;
    int *storage;

    storage = bpf_inode_storage_get(&inode_storage, dentry->d_inode, 0, 0);

    if (!storage)
        return 0;

    bpf_map_update_elem(&test_array, &zero, storage, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
