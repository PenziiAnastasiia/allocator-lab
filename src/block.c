#include <stdbool.h>

#include "block.h"
#include "config.h"
#include "kernel.h"

struct Header *block_split(struct Header *block, size_t size) {
	set_is_busy(block, true);
	size_t free_size = get_curr_size(block) - size;

  if (free_size >= BLOCK_HEADER_SIZE + BLOCK_SIZE_MIN) {
		free_size -= BLOCK_HEADER_SIZE;
		set_curr_size(block, size);

		struct Header *block_r = block_next(block);

		set_prev_size(block_r, size);
		set_curr_size(block_r, free_size);
		set_offset(block_r, get_offset(block) + size + BLOCK_HEADER_SIZE);
		set_is_busy(block_r, false);
		set_is_first(block_r, false);

		if (get_is_last(block)) {
			set_is_last(block, false);
			set_is_last(block_r, true);
		} else {
			set_prev_size(block_next(block_r), free_size);
			set_is_last(block_r, false);
		}
		return block_r;
	}
	return NULL;
}

void block_merge(struct Header *block, struct Header *block_r) {
	size_t size = get_curr_size(block) + get_curr_size(block_r) + BLOCK_HEADER_SIZE;

	set_curr_size(block, size);

	if (get_is_last(block_r)) {
		set_is_last(block, true);
	} else {
		set_prev_size(block_next(block_r), size);
	}
}

void block_dontneed(struct Header *block) {
	size_t size_curr = get_curr_size(block);
  if (size_curr - sizeof(tree_node_type) < ALLOCATOR_PAGE_SIZE) {
    return;
	}

	size_t offset = get_offset(block);
	size_t offset1 = offset + BLOCK_HEADER_SIZE + sizeof(tree_node_type);
	offset1 = (offset1 + ALLOCATOR_PAGE_SIZE - 1) & ~((size_t)ALLOCATOR_PAGE_SIZE - 1);

	size_t offset2 = offset + size_curr + BLOCK_HEADER_SIZE;
  offset2 &= ~((size_t)ALLOCATOR_PAGE_SIZE - 1);

  if (offset1 == offset2) {
    return;
	}

  kernel_reset((char *)block + (offset1 - offset), offset2 - offset1);
}
