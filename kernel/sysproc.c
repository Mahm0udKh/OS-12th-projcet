#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"

#define MAX_USERS 10

// The structure for our passwd-like records
struct user_record {
  char username[32];
  char password[32]; // We will store hashes here later
  uint uid;
  uint gid;
  int active;        // 1 if slot is used, 0 if free
};

// The actual database array
struct user_record user_table[MAX_USERS];

// A helper variable to assign new UIDs automatically
int next_uid = 3;

// ==========================================================
// THE HASH FUNCTION 
// ==========================================================
void
hash_password(char *plaintext, char *hashed)
{
  int i = 0;
  while(plaintext[i] != '\0' && i < 31){
    // A simple shift hash: adds 5 to the ASCII value, wraps safely
    hashed[i] = ((plaintext[i] - 32 + 5) % 95) + 32;
    i++;
  }
  hashed[i] = '\0';
}

// ==========================================================
// SYSTEM CALLS
// ==========================================================

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_useradd(void)
{
  char username[32];
  char password[32];
  int gid; // 1. DECLARE GID HERE

  // 2. Fetch arguments (username, password, and the new GID/Role)
  if(argstr(0, username, 32) < 0 || argstr(1, password, 32) < 0)
    return -1;
  argint(2, &gid); // Your version of argint is void

  // Security check: Only Admin (UID 0) can add users
  if(myproc()->uid != 0)
    return -1;

  // Hash the incoming password
  char hashed_pw[32];
  hash_password(password, hashed_pw);

  // 3. Find an empty slot
  for(int i = 0; i < MAX_USERS; i++){ // 'i' is declared inside the loop here
    if(user_table[i].active == 0){
      safestrcpy(user_table[i].username, username, sizeof(user_table[i].username));
      safestrcpy(user_table[i].password, hashed_pw, sizeof(user_table[i].password));
      
      user_table[i].uid = gid;   // use role_id as UID (doctor=2, patient=1)
      user_table[i].gid = gid;  // 4. NOW 'GID' AND 'I' ARE VALID HERE
      user_table[i].active = 1;
      
      return user_table[i].uid;
    }
  }

  return -1; // Database full
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if(t == SBRK_EAGER || n < 0) {
    if(growproc(n) < 0) {
      return -1;
    }
  } else {
    if(addr + n < addr)
      return -1;
    if(addr + n > TRAPFRAME)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

uint64
sys_whoami(void)
{
  // Returns the uid of the current running process
  return myproc()->uid; 
}

uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_userdel(void)
{
  char username[32];

  // Fetch the username argument from user space
  if(argstr(0, username, 32) < 0)
    return -1;

  // Security check: Only Admin (UID 0) can delete users
  if(myproc()->uid != 0)
    return -1;

  // Failsafe: Prevent deleting the admin account!
  if(strncmp(username, "admin", 32) == 0)
    return -1;

  // Search the database
  for(int i = 0; i < MAX_USERS; i++){
    if(user_table[i].active == 1 && strncmp(user_table[i].username, username, 32) == 0){
      user_table[i].active = 0; // "Soft delete" by marking the slot as inactive
      return 0; // Success
    }
  }

  return -1; // User not found
}

uint64
sys_passwd(void)
{
  char username[32];
  char new_password[32];

  // Fetch both arguments
  if(argstr(0, username, 32) < 0 || argstr(1, new_password, 32) < 0)
    return -1;

  // Search the database
  for(int i = 0; i < MAX_USERS; i++){
    if(user_table[i].active == 1 && strncmp(user_table[i].username, username, 32) == 0){
      
      // Security check: Is the current user the Admin OR the owner of the account?
      if(myproc()->uid == 0 || myproc()->uid == user_table[i].uid){
          
          // Hash the new password
          char hashed_pw[32];
          hash_password(new_password, hashed_pw);

          // Overwrite the old password with the newly hashed one
          safestrcpy(user_table[i].password, hashed_pw, sizeof(user_table[i].password));
          return 0; // Success
      } else {
          return -1; // Permission denied
      }
    }
  }

  return -1; // User not found
}

uint64
sys_login(void)
{
  char username[32];
  char password[32];

  // Fetch the strings from user space
  if(argstr(0, username, 32) < 0 || argstr(1, password, 32) < 0)
    return -1;

  // 1. Hash the incoming plaintext password
  char hashed_input[32];
  hash_password(password, hashed_input);

  // 2. The Failsafe (Checking against the hashed version of "admin", which is "firns")
  if(strncmp(username, "admin", 32) == 0 && strncmp(hashed_input, "firns", 32) == 0){
      myproc()->uid = 0;
      return 1; // Success
  }

  // 3. Check the database
 for(int i = 0; i < MAX_USERS; i++){
    if(user_table[i].active == 1 && 
       strncmp(user_table[i].username, username, 32) == 0 && 
       strncmp(user_table[i].password, hashed_input, 32) == 0) { 
         
         myproc()->uid = user_table[i].uid;
         
         // ---> ADD THIS LINE SO THE KERNEL KNOWS THEIR ROLE <---
         myproc()->gid = user_table[i].gid; 
         
         return 1; 
    }
  }

  return -1; // Login failed
}
// Phase 3.3: Root-Only Audit Reader
uint64
sys_audit_read(void)
{
  if(myproc()->uid != 0) {
    printf("[SECURITY WARNING] Access Denied. UID %d attempted to read the Audit Log!\n", myproc()->uid);
    return -1; // EPERM (Access Denied)
  }
  
  dump_audit();
  return 0;
}

