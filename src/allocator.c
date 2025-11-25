#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "allocator.h"
#include "block.h"
#include "config.h"
#include "kernel.h"
#include "allocator_impl.h"
#include "tree.h"

#define ARENA_SIZE (ALLOCATOR_ARENA_PAGES * ALLOCATOR_PAGE_SIZE)
#define BLOCK_SIZE_MAX (ARENA_SIZE - BLOCK_HEADER_SIZE)
#define SHRINK_SIZE 5

static tree_type blocks_tree = TREE_INITIALIZER;

struct Header *init_arena(size_t size) {
  struct Header *block = kernel_alloc(size);

  if (block != NULL) {
    set_curr_size(block, size - BLOCK_HEADER_SIZE);
    set_prev_size(block, 0);
    set_is_busy(block, false);
    set_is_first(block, true);
    set_is_last(block, true);
    set_offset(block, 0);
  }
  return block;
}

void tree_add_block(struct Header *block) {
    tree_add(&blocks_tree, block_to_node(block), get_curr_size(block));
}

void tree_remove_block(struct Header *block) {
    tree_remove(&blocks_tree, block_to_node(block));
}

void *mem_alloc(size_t size) {
  struct Header *block;

  if (size < BLOCK_SIZE_MIN) {
    size = BLOCK_SIZE_MIN;
  }
  if (size > BLOCK_SIZE_MAX) {
    size = ROUND_BYTES(size) + BLOCK_HEADER_SIZE;

    block = init_arena(size);
    if (block == NULL) {
      return NULL;
    }
    set_is_busy(block, true);
    return block_to_payload(block);
  }
  size = ROUND_BYTES(size);
  tree_node_type *node = tree_find_best(&blocks_tree, size);

  if (node == NULL) {
    block = init_arena(ARENA_SIZE);
    if (block == NULL) {
      return NULL;
    }
  } else {
    tree_remove(&blocks_tree, node);
    block = node_to_block(node);
  }

  struct Header *block_r = block_split(block, size);
  if (block_r != NULL) {
    tree_add_block(block_r);
  }

  return block_to_payload(block);
}

void mem_free(void *ptr) {
  if (ptr == NULL) {
    return;
  }

  struct Header *block = payload_to_block(ptr);
  set_is_busy(block, false);

  if (!get_is_last(block)) {
    struct Header *block_r = block_next(block);
    if (!get_is_busy(block_r)) {
      tree_remove_block(block_r);
      block_merge(block, block_r);
    }
  }
  if (!get_is_first(block)) {
    struct Header *block_l = block_prev(block);
    if (!get_is_busy(block_l)) {
      tree_remove_block(block_l);
      block_merge(block_l, block);
      block = block_l;
    }
  }
  if (get_is_first(block) && get_is_last(block)) {
    kernel_free(block, get_curr_size(block) + BLOCK_HEADER_SIZE);
  } else {
    block_dontneed(block);
    tree_add_block(block);
  }
}

void *mem_realloc(void *ptr, size_t size) {
  struct Header *block;

  if (ptr == NULL) {
    return mem_alloc(size);
  }
  if (size == 0) {
    mem_free(ptr);
    return NULL;
  }
  if (size < BLOCK_SIZE_MIN) {
    size = BLOCK_SIZE_MIN;
  }
  size = ROUND_BYTES(size);

  block = payload_to_block(ptr);
  size_t current_size = get_curr_size(block);
  if (size == current_size) {
    return ptr;
  }
  struct Header *block_r;

  if (size < current_size) {
    if (100 - ((size * 100) / current_size) >= SHRINK_SIZE) {
      block_r = block_split(block, size);
      if (block_r != NULL) {
        tree_add_block(block_r);
      }
    }
    return ptr;
  }

  block_r = block_next(block);
  if (!get_is_last(block) && !get_is_busy(block_r) &&
  (get_curr_size(block_r) + BLOCK_HEADER_SIZE + current_size) >= size) {
    tree_remove_block(block_r);
    block_merge(block, block_r);
    block_r = block_split(block, size);
    if (block_r != NULL) {
      tree_add_block(block_r);
    }
    return ptr;
  }

  void *new_ptr = mem_alloc(size);
  if (new_ptr == NULL) {
    return NULL;
  }

  memcpy(new_ptr, ptr, current_size);
  mem_free(ptr);
  return new_ptr;
}

void show_node(const tree_node_type *node, bool linked) {
    struct Header *block = node_to_block(node);

    printf("[%20p] %20zu %20zu %s%s%s%s\n",
        (void *)block,
        get_curr_size(block), get_prev_size(block),
        get_is_busy(block) ? "busy" : "free",
        get_is_first(block) ? " first " : "",
        get_is_last(block) ? " last" : "",
        linked ? " linked" : "");
}

void mem_show(char *msg) {
  printf("%s:\n", msg);
  if (tree_is_empty(&blocks_tree)) {
    printf("Tree is empty\n");
  }
  else {
    tree_walk(&blocks_tree, show_node);
  }
}
