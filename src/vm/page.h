// SOS Implementation project 3
#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
#include "threads/thread.h"

#define list_elem_to_hash_elem(LIST_ELEM)                       \
        list_entry(LIST_ELEM, struct hash_elem, list_elem)

#define PG_NUM(ADDR) ((uintptr_t)ADDR >> 12)

#define TYPE_EXEC 0
#define TYPE_FILE 1

#define LOC_NONE 0
#define LOC_PHYS 1
#define LOC_SWAP 2
#define LOC_FILE 3

struct list frame_table;

struct frame_table_entry
{
    unsigned frame_number;                     
    struct sPage_table_entry *s_pte;     // Mapped supplemental page table entry 
    struct thread *thread;               
    struct list_elem elem;               // Frame table list element
};

struct sPage_table_entry
{
    uint8_t type;       // Three Virtual Address types : VM_EXE, VM_FILE, VM_SWAP, VM_STACK
    uint8_t location;
    unsigned page_number;  
    bool writable;      
    struct file *file;
    struct frame_table_entry *fte;   // Frame Table Entry
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    struct hash_elem elem;      // Supplementary Page Table hash element 
    uint32_t slot_number;       // Indicate location in swap slot when swapped in swap device
};

unsigned get_hash(unsigned);
unsigned s_pt_hash_func(const struct hash_elem *, void *);
bool s_pt_less_func (const struct hash_elem *, const struct hash_elem *);
struct sPage_table_entry *find_s_pte (void *);
void insert_frame (struct frame_table_entry *);
struct frame_table_entry *find_eviction_frame ();
void delete_frame_entry (struct frame_table_entry *);
void s_pte_fte_ste_deallocator (struct hash_elem *, void *);

#endif
