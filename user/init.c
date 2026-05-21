#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"
#include "kernel/fs.h"
#include "kernel/file.h"
#include "user/user.h"
#include "kernel/fcntl.h"

char *argv[] = { "sh", 0 };

int
main(void)
{
  int pid, wpid;

  if(open("console", O_RDWR) < 0){
    mknod("console", CONSOLE, 0);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr
    useradd("admin",  "admin", 0);
    useradd("doctor",  "doc123", 2);
    useradd("patient", "pat123",  1);



  // The Infinite Boot Loop
  for(;;){
    char user[32];
    char pass[32];

    // 1. The Custom Prompt
    printf("\nxv6 Medical Device Login\n");
    printf("Username: ");
    gets(user, sizeof(user));
    user[strlen(user)-1] = 0; // Strip the newline character

    printf("Password: ");
    gets(pass, sizeof(pass));
    pass[strlen(pass)-1] = 0; // Strip the newline character

    // 2. The Verification
    if(login(user, pass) < 0){
        printf("Access Denied.\n");
        continue; // Loop back to the prompt
    }

    printf("Access Granted.\n");

    // 3. Spawn the shell ONLY if authenticated
    pid = fork();
    if(pid < 0){
      printf("init: fork failed\n");
      exit(1);
    }
    if(pid == 0){
      exec("sh", argv);
      printf("init: exec sh failed\n");
      exit(1);
    }

    while((wpid=wait((int *) 0)) >= 0 && wpid != pid)
      printf("zombie!\n");
  }
}
