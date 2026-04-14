#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
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

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcaec5711, "module_layout" },
	{ 0xd31ccb06, "of_machine_is_compatible" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x3ce4ca6f, "disable_irq" },
	{ 0x85bd1608, "__request_region" },
	{ 0xd4cdbc1b, "gpiod_direction_output" },
	{ 0x714799fe, "devm_pwm_get" },
	{ 0xd39fa6ab, "__kfifo_alloc" },
	{ 0x40342aef, "pwm_apply_state" },
	{ 0xb43f9365, "ktime_get" },
	{ 0xa6970398, "__kfifo_to_user_r" },
	{ 0x78770421, "device_destroy" },
	{ 0x58b75b34, "devm_gpiod_get" },
	{ 0x615c316, "__register_chrdev" },
	{ 0xb1ad28e0, "__gnu_mcount_nc" },
	{ 0xae353d77, "arm_copy_from_user" },
	{ 0x67ea780, "mutex_unlock" },
	{ 0x5af58d5d, "__platform_driver_register" },
	{ 0x51a910c0, "arm_copy_to_user" },
	{ 0x81745c35, "of_property_read_variable_u8_array" },
	{ 0x5bbe49f4, "__init_waitqueue_head" },
	{ 0x5f754e5a, "memset" },
	{ 0xdbdf6c92, "ioport_resource" },
	{ 0xf3d0b495, "_raw_spin_unlock_irqrestore" },
	{ 0xe346f67a, "__mutex_init" },
	{ 0xc5850110, "printk" },
	{ 0x1d37eeed, "ioremap" },
	{ 0xdec6108b, "devm_gpiod_get_index" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xc271c3be, "mutex_lock" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x5d3eb04, "device_create" },
	{ 0x92d5838e, "request_threaded_irq" },
	{ 0x8e865d3c, "arm_delay_ops" },
	{ 0x42160169, "flush_workqueue" },
	{ 0xfe487975, "init_wait_entry" },
	{ 0xe9d59def, "module_put" },
	{ 0x86332725, "__stack_chk_fail" },
	{ 0x8ddd8aad, "schedule_timeout" },
	{ 0x7c9a7371, "clk_prepare" },
	{ 0x2ec524ad, "__kfifo_in_r" },
	{ 0x5fab16e6, "of_find_compatible_node" },
	{ 0xb60bb752, "devm_clk_get" },
	{ 0xde55e795, "_raw_spin_lock_irqsave" },
	{ 0xdb760f52, "__kfifo_free" },
	{ 0x76d9b876, "clk_set_rate" },
	{ 0x3dcf1ffa, "__wake_up" },
	{ 0x647af474, "prepare_to_wait_event" },
	{ 0x2cfde9a2, "warn_slowpath_fmt" },
	{ 0xfcec0987, "enable_irq" },
	{ 0x9d669763, "memcpy" },
	{ 0xf4d64ff, "gpiod_to_irq" },
	{ 0xedc03953, "iounmap" },
	{ 0xf0462214, "class_destroy" },
	{ 0x49970de8, "finish_wait" },
	{ 0x8f678b07, "__stack_chk_guard" },
	{ 0xb2d48a2e, "queue_work_on" },
	{ 0x40e518c8, "platform_driver_unregister" },
	{ 0xd38d8d6f, "of_property_read_variable_u32_array" },
	{ 0x5a3de6d1, "gpiod_set_value" },
	{ 0xa21d4a12, "of_node_put" },
	{ 0x85a03920, "devm_kmalloc" },
	{ 0x84e8af7f, "__class_create" },
	{ 0xdf9208c0, "alloc_workqueue" },
	{ 0x836feaf2, "try_module_get" },
	{ 0xaa6901ac, "__kfifo_out_r" },
	{ 0xc1514a3b, "free_irq" },
};

MODULE_INFO(depends, "");

MODULE_ALIAS("of:N*T*Ceconet-gpio");
MODULE_ALIAS("of:N*T*Ceconet-gpioC*");

MODULE_INFO(srcversion, "273AD39FE9518B6C8333FC1");
