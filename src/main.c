#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "allocator.h"
#include "tester.h"
#include "block.h"

static void *buf_alloc(size_t size) {
    char *buf = mem_alloc(size);
    size_t i;
    if (buf != NULL)
        for (i = 0; i < size; ++i)
            buf[i] = (char)rand();
    return buf;
}

int main(void) {
  // manual
  void *ptr1, *ptr2, *ptr3, *ptr4;
  ptr1 = buf_alloc(2000);
  mem_show("alloc(995)");
  ptr2 = buf_alloc(40);
  mem_show("alloc(40)");
  ptr3 = buf_alloc(30);
  mem_show("alloc(30)");
  ptr4 = buf_alloc(50);
  mem_show("allocs");
  ptr2 = mem_realloc(ptr2, 65600);
  mem_show("realloc(ptr2)");
  ptr1 = mem_realloc(ptr1, 1910);
  mem_show("realloc(ptr1)");
  mem_free(ptr1);
  mem_show("free(ptr1)");
  mem_free(ptr3);
  mem_show("free(ptr3)");
  mem_free(ptr2);
  mem_show("free(ptr2)");
  mem_free(ptr4);
  mem_show("free(ptr4)");

  // tester
  srand(100);
  tester(true);
}
