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

extern struct __eb_device * eb_find_station (uint8_t, struct __econet_packet_aun *);
extern uint8_t eb_enqueue_output (struct __eb_device *, struct __econet_packet_aun *, uint16_t, struct __eb_device *);
extern void eb_add_stats (pthread_mutex_t *, uint64_t *, uint16_t);
extern void eb_fast_priv_notify (struct __eb_device *, uint8_t, uint8_t, uint8_t);

