/* Wait for a subprocess to finish. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  printf("\nok\n");
  msg ("wait(exec()) = %d", wait (exec ("child-simple")));
}
  