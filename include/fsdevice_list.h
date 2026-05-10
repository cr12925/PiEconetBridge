static struct { fs_device * (*register_function) (void); } fs_device_driver_list[] = {
	FSDEVICE_REGISTER(fsd_ramdisk_register),
	NULL
	};
