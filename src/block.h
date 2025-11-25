#include <stdbool.h>

#include "allocator_impl.h"
#include "tree.h"

struct Header {
	size_t curr_size;
	size_t prev_size;
	size_t offset;
};

#define BLOCK_HEADER_SIZE ROUND_BYTES(sizeof(struct Header))
#define BLOCK_SIZE_MIN ROUND_BYTES(sizeof(tree_node_type))
#define BLOCK_FLAGS_MASK ((size_t)7)
#define BLOCK_BUSY_MASK 0x1
#define BLOCK_FIRST_MASK 0x2
#define BLOCK_LAST_MASK 0x4

struct Header *block_split(struct Header *, size_t);
void block_merge(struct Header *, struct Header *);
void block_dontneed(struct Header *);

inline void *block_to_payload(struct Header *block) {
	return (void *)((char *)block + BLOCK_HEADER_SIZE);
}

inline struct Header *payload_to_block(void *payload) {
	return (struct Header *)((char *)payload - BLOCK_HEADER_SIZE);
}

inline tree_node_type *block_to_node(struct Header *block) {
  return block_to_payload(block);
}

inline struct Header *node_to_block(tree_node_type *node) {
  return payload_to_block(node);
}

// setter and getter for current size
inline void set_curr_size(struct Header *block, size_t size) {
	size_t flags = block->curr_size & BLOCK_FLAGS_MASK;
	block->curr_size = size;
	block->curr_size |= flags;
}

inline size_t get_curr_size(struct Header *block) {
	return block->curr_size & ~BLOCK_FLAGS_MASK;
}

// setter and getter for previous size
inline void set_prev_size(struct Header *block, size_t size) {
	block->prev_size = size;
}

inline size_t get_prev_size(struct Header *block) {
	return block->prev_size;
}

// setter and getter for offset size
inline void set_offset(struct Header *block, size_t offset) {
	block->offset = offset;
}

inline size_t get_offset(struct Header *block) {
	return block->offset;
}

// setter and getter for is_busy flag
inline void set_is_busy(struct Header *block, bool state) {
	if (state) {
		block->curr_size |= BLOCK_BUSY_MASK;
	} else {
		 block->curr_size &= ~(size_t)BLOCK_BUSY_MASK;
	}
}

inline bool get_is_busy(struct Header *block) {
	return block->curr_size & BLOCK_BUSY_MASK;
}

// setter and getter for is_first flag
inline void set_is_first(struct Header *block, bool state) {
	if (state) {
		block->curr_size |= BLOCK_FIRST_MASK;
	} else {
		 block->curr_size &= ~(size_t)BLOCK_FIRST_MASK;
	}
}

inline bool get_is_first(struct Header *block) {
	return block->curr_size & BLOCK_FIRST_MASK;
}

// setter and getter for is_last flag
inline void set_is_last(struct Header *block, bool state) {
	if (state) {
		block->curr_size |= BLOCK_LAST_MASK;
	} else {
		 block->curr_size &= ~(size_t)BLOCK_LAST_MASK;
	}
}

inline bool get_is_last(struct Header *block) {
	return block->curr_size & BLOCK_LAST_MASK;
}

inline struct Header *block_next(struct Header *block) {
	return (struct Header *)((char *)block + BLOCK_HEADER_SIZE + get_curr_size(block));
}

inline struct Header *block_prev(struct Header *block) {
	return (struct Header *)((char *)block - BLOCK_HEADER_SIZE - get_prev_size(block));
}
