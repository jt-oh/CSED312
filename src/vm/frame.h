#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <list.h>
#include "vm/page.h"
#include "threads/thread.h"

struct frame_table_entry
{
    unsigned frame_number;                     
    struct sPage_table_entry *s_pte;     // Mapped supplemental page table entry 
    struct thread *thread;               
    struct list_elem elem;               // Frame table list element
    bool pin;
};

void frame_init ();
void insert_frame (struct frame_table_entry *);
void delete_frame_entry (struct frame_table_entry *);
struct frame_table_entry *frame_alloc();

#endif