// FS Parameter flag bytes for the communications between FS and the *FAST handler in the Bridge

#define ECONET_HPBFS_ACORNHOME 0x01
#define ECONET_HPBFS_SJFUNC 0x02
#define ECONET_HPBFS_BIGCHUNKS 0x04
#define ECONET_HPBFS_INFCOLON 0x08
#define ECONET_HPBFS_MANYHANDLE 0x10
#define ECONET_HPBFS_MDFSINFO 0x20

#define FS_CONFIG_ACORNHOME 	0x01
#define FS_CONFIG_SJFUNC	0x02
#define FS_CONFIG_BIGCHUNKS	0x04
#define FS_CONFIG_INFCOLON	0x08
#define FS_CONFIG_MANYHANDLE	0x10
#define FS_CONFIG_MDFSINFO	0x20
#define FS_CONFIG_PIFSPERMS	0x40
#define FS_CONFIG_MASKDIRWRR	0x80

extern void fs_setup(void);

