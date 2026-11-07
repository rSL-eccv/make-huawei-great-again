/* Huawei Nova 15 Max (CHZ-LX1) — Kirin 8000, kernel 5.10.43 (EMUI 14.2.0)
 * Compact waiter (waiter_word=0, PSELECT_SHIFT=0)
 *
 * Struct offsets: verified via Ghidra disassembly of task_blocks_on_rt_mutex,
 *   remove_waiter, get_task_cred, __set_task_comm, __arm64_sys_getpid.
 *   NOTE: Huawei's task_struct layout differs significantly from GKI 5.10
 *   (cred at 0x950 vs GKI 0x780; pi_* at 0xA40..0xA80 vs GKI 0x86C..0x898).
 *   Do NOT use STRUCT_OFFSETS_5_10 for this device.
 *
 * Kernel symbols: from /proc/kallsyms (unslid) on device.
 *
 * Path: sysctl route only (boot_id ctl_table hijack). fops not required.
 */

OFFSETS_ENTRY("5.10.43",
  .kernel_phys_load = 0xa8000000ULL,
  .phys_offset = 0x80000000ULL,

  /* ===== Kernel symbols (from kallsyms) ===== */
  .off_init_task = 0x3e30c80ULL,
  .off_init_cred = 0x3cb3098ULL,
  .off_init_uts_ns = 0,
  .off_empty_zero_page = 0,
  .off_root_task_group = 0x2f20040ULL,
  .off_selinux_enforcing = 0x407ab50ULL,   /* selinux_state+0 */
  .off_kptr_restrict = 0,
  .off_selinux_blob_sizes = 0,
  .off_security_hook_heads = 0,
  .off_kmalloc_caches = 0,

  /* ===== fops symbols (not used by sysctl route) ===== */
  .off_anon_pipe_buf_ops = 0,
  .off_ashmem_misc_fops = 0x3d36e68,
  .off_ashmem_fops = 0x2ff5488,
  .off_ashmem_ioctl = 0,
  .off_ashmem_compat_ioctl = 0,
  .off_ashmem_mmap = 0,
  .off_ashmem_open = 0,
  .off_ashmem_release = 0,
  .off_ashmem_show_fdinfo = 0,
  .off_configfs_read_iter = 0,
  .off_configfs_bin_write_iter = 0,
  .off_copy_splice_read = 0,
  .off_noop_llseek = 0,
  .off_cap_capable_active = 0,

  /* ===== KASLR slide symbols (from kallsyms) ===== */
  .off_slide_nfulnl_logger = 0x389aa58ULL,
  .off_slide_loggers_0_1 = 0x389a980ULL,
  .off_slide_boot_id = 0x40c1a04ULL,   /* sysctl_bootid */

  /* ===== UMH (not used) ===== */
  .off_system_unbound_wq = 0,
  .off_call_usermodehelper_exec_work = 0,

  /* ===== task_struct fields (Huawei custom layout, from Ghidra) ===== */
  .task_prio = 0x84,
  .task_normal_prio = 0x8c,
  .task_sched_task_group = 0,        /* not used */
  .task_pi_lock = 0xa40,             /* do_raw_spin_lock(task+0xa40) */
  .task_pi_waiters = 0xa68,          /* task->pi_waiters.rb_root.rb_node */
  .task_pi_top_task = 0xa78,         /* task->pi_waiters.rb_leftmost → top */
  .task_pi_blocked_on = 0xa80,       /* task->pi_blocked_on (waiter ptr) */
  .task_pid = 0x7d8,                 /* thread_pid pointer (from prctl disasm) */
  .task_tgid = 0x7dc,
  .task_real_parent = 0,
  .task_atomic_flags = 0,
  .task_real_cred = 0x948,           /* get_task_cred: param+0x948 */
  .task_cred = 0x950,                /* __arm64_sys_getuid: current+0x950 */
  .task_comm = 0x960,                /* __set_task_comm: param+0x960 */
  .task_tasks = 0,
  .task_seccomp = 0,
  .mm_owner = 0x3a0,                 /* mm->owner (standard 5.10, not changed) */
  .waiter_compact = 1,               /* 5.10 compact waiter (10 words) */
  /* ===== .kimage_text_base = 0xffffffc010000000ULL, ===== */

  /* ===== file_operations fields (not used by sysctl route) ===== */
  .fops_llseek = 0x08,
  .fops_read = 0x10,
  .fops_write = 0x18,
  .fops_read_iter = 0x20,
  .fops_write_iter = 0x28,
  .fops_ioctl = 0,
  .fops_compat_ioctl = 0,
  .fops_mmap = 0,
  .fops_open = 0x70,
  .fops_release = 0x80,
  .fops_splice_read = 0xc8,
  .fops_show_fdinfo = 0xe0,
),