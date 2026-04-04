#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xc1514a3b, "free_irq" },
	{ 0x33fcf44a, "__kfifo_out_r" },
	{ 0x54ca6c49, "try_module_get" },
	{ 0x9e7d6bd0, "__udelay" },
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0x36a78de3, "devm_kmalloc" },
	{ 0x469438cc, "of_node_put" },
	{ 0x96501a94, "gpiod_set_value" },
	{ 0x80192c9b, "of_property_read_variable_u32_array" },
	{ 0x61fd46a9, "platform_driver_unregister" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x92540fbf, "finish_wait" },
	{ 0x6775d5d3, "class_destroy" },
	{ 0xedc03953, "iounmap" },
	{ 0xaf56600a, "arm64_use_ng_mappings" },
	{ 0xa7493c03, "gpiod_to_irq" },
	{ 0x4829a47e, "memcpy" },
	{ 0xfcec0987, "enable_irq" },
	{ 0x8c26d495, "prepare_to_wait_event" },
	{ 0xe2964344, "__wake_up" },
	{ 0x76d9b876, "clk_set_rate" },
	{ 0xdb760f52, "__kfifo_free" },
	{ 0x34db050b, "_raw_spin_lock_irqsave" },
	{ 0xe856a90, "devm_clk_get" },
	{ 0x50c7e6ee, "of_find_compatible_node" },
	{ 0x3955fcf6, "__kfifo_in_r" },
	{ 0x7c9a7371, "clk_prepare" },
	{ 0x92997ed8, "_printk" },
	{ 0x8ddd8aad, "schedule_timeout" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x6cbbfc54, "__arch_copy_to_user" },
	{ 0xe2fdcc90, "of_machine_compatible_match" },
	{ 0x4e51e4b4, "module_put" },
	{ 0xfe487975, "init_wait_entry" },
	{ 0x2a10607e, "devm_kfree" },
	{ 0x92d5838e, "request_threaded_irq" },
	{ 0x6e26cac4, "device_create" },
	{ 0x59c02473, "class_create" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xe58ce88c, "devm_gpiod_get_index" },
	{ 0x3e2fcf89, "pwm_apply_might_sleep" },
	{ 0xd35cce70, "_raw_spin_unlock_irqrestore" },
	{ 0xdbdf6c92, "ioport_resource" },
	{ 0xdcb764ad, "memset" },
	{ 0x9166fc03, "__flush_workqueue" },
	{ 0xd9a5ea54, "__init_waitqueue_head" },
	{ 0x57624c0a, "of_property_read_variable_u8_array" },
	{ 0xfa474811, "__platform_driver_register" },
	{ 0xeae3dfd6, "__const_udelay" },
	{ 0x418c10ec, "__register_chrdev" },
	{ 0x3250fd9c, "devm_gpiod_get" },
	{ 0x607a5c68, "device_destroy" },
	{ 0x2484adc3, "__kfifo_to_user_r" },
	{ 0xb43f9365, "ktime_get" },
	{ 0x12a4e128, "__arch_copy_from_user" },
	{ 0x139f2189, "__kfifo_alloc" },
	{ 0x4ab50196, "devm_pwm_get" },
	{ 0x40863ba1, "ioremap_prot" },
	{ 0x4fb5fdc7, "gpiod_direction_output" },
	{ 0x85bd1608, "__request_region" },
	{ 0x3ce4ca6f, "disable_irq" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x474e54d2, "module_layout" },
};

MODULE_INFO(depends, "");

MODULE_ALIAS("of:N*T*Ceconet-gpio");
MODULE_ALIAS("of:N*T*Ceconet-gpioC*");

MODULE_INFO(srcversion, "58DC3B92717149560626485");
