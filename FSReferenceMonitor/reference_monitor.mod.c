#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

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
	{ 0x30ff7695, "module_layout" },
	{ 0x1197bf4f, "param_ops_ulong" },
	{ 0xf9418c06, "param_ops_int" },
	{ 0xbc0b22e9, "param_array_ops" },
	{ 0x33a21a09, "pv_ops" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x21271fd0, "copy_user_enhanced_fast_string" },
	{ 0x1f199d24, "copy_user_generic_string" },
	{ 0xecdcabd2, "copy_user_generic_unrolled" },
	{ 0xa22a96f7, "current_task" },
	{ 0xf8608e9e, "crypto_destroy_tfm" },
	{ 0x37a0cba, "kfree" },
	{ 0x610e4df9, "crypto_shash_digest" },
	{ 0x754d539c, "strlen" },
	{ 0x4f00afd3, "kmem_cache_alloc_trace" },
	{ 0xac1c4313, "kmalloc_caches" },
	{ 0x39c70837, "crypto_alloc_shash" },
	{ 0x92997ed8, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x2c319631, "filp_close" },
	{ 0x797dafb0, "kernel_write" },
	{ 0x70aa6c73, "filp_open" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "23E2D3D4CC6B0C10570792D");
