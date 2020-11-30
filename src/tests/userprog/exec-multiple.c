/* Executes and waits for multiple child processes. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  wait (exec ("child-simple"));
//	printf("child1 finish!\n");
  wait (exec ("child-simple"));
	//printf("child2 finish!\n");
  wait (exec ("child-simple"));
	//printf("child3 finish!\n");
  wait (exec ("child-simple"));
	//printf("child4 finish!\n");
}
