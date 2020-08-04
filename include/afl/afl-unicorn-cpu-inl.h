/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of Unicorn 1.0.1. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/types.h>

#ifdef __linux__

#include <sys/shm.h>
#include <sys/wait.h>

#elif _WIN32

// TODO

#endif

#include "config.h"

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_UNICORN_CPU_SNIPPET1 do { \
    afl_request_tsl(env->uc, pc, cs_base, flags); \
    hook_tb_translate(env->uc, pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_UNICORN_CPU_SNIPPET2 do { \
    if(uc->afl_first_instr == 0) { \
      afl_setup(uc); \
      /* afl_forkserver(env); */ \
      uc->afl_first_instr = 1; \
    } \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* Function declarations. */

static void afl_setup(struct uc_struct *uc);
static void afl_forkserver(CPUArchState*);
static inline void afl_maybe_log(struct uc_struct *uc, unsigned long);

static void afl_wait_tsl(CPUArchState*, int);
static void afl_request_tsl(struct uc_struct *uc, target_ulong, target_ulong, uint64_t);

static TranslationBlock *tb_find_slow(CPUArchState*, target_ulong,
                                      target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(struct uc_struct *uc) {

  uc->bb_count = 0;
  uc->inst_count = 0;
  if (uc->bb_count_interrupt == 0) {
    uc->bb_count_interrupt = pow(2,23)-1;
  }
  if (uc->afl_inst_rms == 0) {
    uc->afl_inst_rms = (1 << 16);
  }
  // Debug AFL tracing performance with fake area_ptr
  // uc->afl_area_ptr = calloc(1, MAP_SIZE);
  unsigned int r = 100;
  uc->afl_inst_rms = MAP_SIZE * r / 100;

#ifdef __linux__

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    uc->afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    uc->afl_area_ptr = shmat(shm_id, NULL, 0);

    if (uc->afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) uc->afl_area_ptr[0] = 1;
  }

#elif _WIN32

  // TODO support for winafl

#endif
}

/* Fork server logic, invoked once we hit first emulated instruction. */

static void afl_forkserver(CPUArchState *env) {

#ifdef __linux__

  static unsigned char tmp[4];

  if (!env->uc->afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  env->uc->afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll 
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      env->uc->afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }


#elif _WIN32

// TODO

#endif

}

/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(struct uc_struct *uc, target_ulong pc, target_ulong cb, uint64_t flags) {
  struct afl_tsl t;

  if (!uc->afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState *env, int fd) {
  struct afl_tsl t;

  while (1) {
    /* Broken pipe means it's time to return to the fork server routine. */
    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;
    tb_find_slow(env, t.pc, t.cs_base, t.flags);
  }

  close(fd);
}

// Use a pre- and post- translate hook
// Pre can be used to add a hook on that block, if needed, without flushing the entire cache
// Post can be used to examine the translated block
static void hook_tb_translate(struct uc_struct *uc, target_ulong pc, target_ulong cb, uint64_t flags) {
  struct hook *hook;
  HOOK_FOREACH_VAR_DECLARE;
  HOOK_FOREACH(uc, hook, UC_HOOK_INTR) {
      ((uc_cb_hookintr_t)hook->callback)(uc, 0xfbfbfbfb, hook->user_data);
  }
}
