#include <linux/btrfs.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <stddef.h>
#include <stdio.h>
_Static_assert(sizeof(struct btrfs_ioctl_search_key) == 104, "search key");
_Static_assert(sizeof(struct btrfs_ioctl_search_args) == 4096, "search args");
_Static_assert(sizeof(struct btrfs_ioctl_defrag_range_args) == 48, "defrag args");
_Static_assert(sizeof(struct fiemap_extent) == 56, "fiemap extent");
_Static_assert(offsetof(struct fiemap, fm_extents) == 32, "fiemap header");
_Static_assert(BTRFS_IOC_GET_FEATURES == 0x80189439UL, "features request");
_Static_assert(FS_IOC_GETFLAGS == 0x80086601UL, "flags request");
_Static_assert(FS_IOC_FIEMAP == 0xc020660bUL, "fiemap request");
_Static_assert(BTRFS_IOC_TREE_SEARCH == 0xd0009411UL, "tree search request");
_Static_assert(BTRFS_IOC_DEFRAG_RANGE == 0x40309410UL, "defrag request");
int main(void) { puts("10 Linux UAPI layout/request assertions passed"); }
