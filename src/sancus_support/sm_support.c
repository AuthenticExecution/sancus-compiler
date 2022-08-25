#include "sm_support.h"

// The register allocator chokes without optimizations.
__attribute__((optimize("-O2")))
sm_id sancus_enable_wrapped(struct SancusModule* sm, unsigned nonce, void* tag)
{
    asm("mov %1, r9\n\t"
        "mov %2, r10\n\t"
        "mov %3, r11\n\t"
        "mov %4, r12\n\t"
        "mov %5, r13\n\t"
        "mov %6, r14\n\t"
        "mov %7, r15\n\t"
        ".word 0x1381\n\t"
        "mov r15, %0"
        : "=m"(sm->id)
        : "m"(tag), "m"(nonce),
          "m"(sm->vendor_id),
          "m"(sm->public_start), "m"(sm->public_end),
          "m"(sm->secret_start), "m"(sm->secret_end)
        : "9", "10", "11", "12", "13", "14", "15");

    return sm->id;
}

sm_id sancus_enable(struct SancusModule* sm)
{
    return sancus_enable_wrapped(sm, 0, NULL);
}

int is_buffer_outside_region(void *start_p, void *end_p,
    void *buf_p, size_t len) {
  uintptr_t start = (uintptr_t) start_p;
  uintptr_t end   = (uintptr_t) end_p;
  uintptr_t buf   = (uintptr_t) buf_p;
  uintptr_t buf_end;
  
  // make sure start < end, otherwise return false
  if (start >= end) {
    return 0;
  }

  if(len > 0) {
    buf_end = buf + len - 1;
  }
  else {
    buf_end = buf;
  }

  /* check for int overflow and finally validate `buf` falls outside */ 
  if( (buf <= buf_end) && ((end <= buf) || (start > buf_end))) {
    return 1;
  }

  return 0;
}