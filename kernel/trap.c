#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[];
void kernelvec();
extern int devintr();

// ==========================================
// Phase 3.1: Trap Name Mapping
// ==========================================
char*
trapname(uint64 scause)
{
  switch(scause) {
    case 8: return "System Call";
    case 12: return "Instruction Page Fault";
    case 13: return "Load Page Fault";
    case 15: return "Store Page Fault";
    default: return "Unknown Exception";
  }
}

// ==========================================
// Phase 3.2: Kernel Audit Ring Buffer
// ==========================================
#define AUDIT_SIZE 100

struct audit_record {
  int pid;
  uint uid;
  int syscall_num;
  uint tick_count;
};

struct audit_record ring_buffer[AUDIT_SIZE];
int audit_index = 0;

void record_audit(int pid, uint uid, int sys_num) {
  ring_buffer[audit_index].pid = pid;
  ring_buffer[audit_index].uid = uid;
  ring_buffer[audit_index].syscall_num = sys_num;
  ring_buffer[audit_index].tick_count = ticks; 
  audit_index = (audit_index + 1) % AUDIT_SIZE; 
}

void dump_audit(void) {
  printf("\n=== KERNEL AUDIT RING BUFFER ===\n");
  for(int i = 0; i < AUDIT_SIZE; i++) {
    if(ring_buffer[i].pid != 0) { 
      printf("Tick: %d | PID: %d | UID: %d | Syscall: %d\n", 
        ring_buffer[i].tick_count, ring_buffer[i].pid, ring_buffer[i].uid, ring_buffer[i].syscall_num);
    }
  }
  printf("================================\n");
}
// ==========================================

void trapinit(void) { initlock(&tickslock, "time"); }
void trapinithart(void) { w_stvec((uint64)kernelvec); }

uint64
usertrap(void)
{
  int which_dev = 0;
  if((r_sstatus() & SSTATUS_SPP) != 0) panic("usertrap: not from user mode");

  w_stvec((uint64)kernelvec);  
  struct proc *p = myproc();
  p->trapframe->epc = r_sepc();
  uint64 cause = r_scause();

  // =====================================================================
  // Phase 3: Hardware Logging
  // =====================================================================
  if((cause & 0x8000000000000000L) == 0){ 
    int syscall_num = p->trapframe->a7;
    
    // Silence SYS_read (5) and SYS_write (16) to keep console usable
    if(cause == 8 && (syscall_num == 5 || syscall_num == 16)) {
        // Do nothing
    } else {
        printf("[TRAP AUDIT] PID: %d | UID: %d | Trap: %s | EPC: %p\n", 
                p->pid, p->uid, trapname(cause), (void*)p->trapframe->epc);
        
        if(cause == 8) record_audit(p->pid, p->uid, syscall_num);
    }
  }

  if(cause == 8){
    if(killed(p)) kexit(-1);
    p->trapframe->epc += 4;
    intr_on();
    syscall();
  } else if((which_dev = devintr()) != 0){
    // ok
  } else if((cause == 15 || cause == 13) &&
            vmfault(p->pagetable, r_stval(), (cause == 13)? 1 : 0) != 0) {
    // page fault
  } else {
    printf("usertrap(): unexpected scause 0x%lx pid=%d\n", cause, p->pid);
    printf("            sepc=0x%lx stval=0x%lx\n", r_sepc(), r_stval());
    setkilled(p);
  }

  if(killed(p)) kexit(-1);
  if(which_dev == 2) yield();
  prepare_return();
  return MAKE_SATP(p->pagetable);
}

void prepare_return(void) {
  struct proc *p = myproc();
  intr_off();
  uint64 trampoline_uservec = TRAMPOLINE + (uservec - trampoline);
  w_stvec(trampoline_uservec);
  p->trapframe->kernel_satp = r_satp();         
  p->trapframe->kernel_sp = p->kstack + PGSIZE; 
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();         
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; 
  x |= SSTATUS_SPIE; 
  w_sstatus(x);
  w_sepc(p->trapframe->epc);
}

void kerneltrap() {
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0) panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0) panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    printf("scause=0x%lx sepc=0x%lx stval=0x%lx\n", scause, r_sepc(), r_stval());
    panic("kerneltrap");
  }
  if(which_dev == 2 && myproc() != 0) yield();
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void clockintr() {
  if(cpuid() == 0){
    acquire(&tickslock);
    ticks++;
    wakeup(&ticks);
    release(&tickslock);
  }
  w_stimecmp(r_time() + 1000000);
}

int devintr() {
  uint64 scause = r_scause();
  if(scause == 0x8000000000000009L){
    int irq = plic_claim();
    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }
    if(irq) plic_complete(irq);
    return 1;
  } else if(scause == 0x8000000000000005L){
    clockintr();
    return 2;
  } else {
    return 0;
  }
}
