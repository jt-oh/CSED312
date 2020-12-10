#include "vm/page.h"
#include "threads/pte.h"
#include <stdlib.h>
#include <stdio.h>
#include "userprog/syscall.h"
#include "userprog/exception.h"

unsigned get_hash(unsigned page_number){      // Get Hash value with page number
	return page_number % 1024;
}

unsigned s_pt_hash_func(const struct hash_elem *e, void *aux){                          // hash_hash_function
  struct sPage_table_entry *s_pte;
  unsigned page_number;
  unsigned hash_value;

  ASSERT(e != NULL);

  s_pte = hash_entry(e, struct sPage_table_entry, elem);      // get Supplementary Page Table Entry with hash_elem e
  page_number = s_pte->page_number;                                 // get Virtual Address with Supplementary Page Table Entry
  hash_value = get_hash(page_number);                           // get hash value with MSB 20 bits of Virtual Address 

  return hash_value;
}

bool s_pt_less_func (const struct hash_elem *a_, const struct hash_elem *b_){           // hash_less_function
  struct sPage_table_entry *a = hash_entry(a_, struct sPage_table_entry, elem);
  struct sPage_table_entry *b = hash_entry(b_, struct sPage_table_entry, elem);

  ASSERT (a != NULL);
  ASSERT (b != NULL);

  return a->page_number < b->page_number;
}

struct sPage_table_entry *find_s_pte (void *vaddr){
  unsigned page_number;
  unsigned hash;
  struct list *bucket;
  struct thread *t = thread_current();
  struct list_elem *e;
  struct sPage_table_entry *result;

	//printf("Hi! find_s_pte!\n");
    
  page_number = PG_NUM(vaddr);                       // get Page Number of vaddr
	
	//printf("find_s_pte get page number!\n");

  hash = get_hash(page_number);    						// get hash of vaddr

	//printf("find_s_pte got hash!\n");

	//printf("tid %d\n", t->tid);

  bucket = &t->sPage_table.buckets[hash % t->sPage_table.bucket_cnt];           // get bucket with hash in sPage_Table

	//printf("find_spte got bucket!\n");

  if(list_empty(bucket))                           // Case: Bucket is empty
    return NULL;

	//printf("find_s_pte before get hash element\n");
	//printf("bucket size : %d \n", list_size(bucket));

  for(e = list_begin(bucket); e != list_end(bucket); e = list_next(e)){
    result = hash_entry(list_elem_to_hash_elem(e), struct sPage_table_entry, elem);
		//printf("check! page number %x\n", result->page_number);
    if(result->page_number == page_number){
     //printf("find hash element\n");
		 return result;                                // Case: Find vaddr in sPage_table
  	}
	}

	//printf("can't find hash element\n");

  return NULL;                                      // Case: Can't find vaddr in sPage_table
}

void s_pte_fte_ste_deallocator (struct hash_elem *e, void *aux){
  ASSERT (e != NULL);

  struct sPage_table_entry *s_pte;

  // Get s_pte
  s_pte = hash_entry(e, struct sPage_table_entry, elem);    

	//printf("delete %p sPte with %p frame_number\n", s_pte->page_number, s_pte->fte->frame_number);
  // Deallocate related frame table entry or swap table entry
  if(s_pte->location == LOC_PHYS){
		palloc_free_page((uintptr_t)s_pte->fte->frame_number << 12);
		pagedir_clear_page(s_pte->fte->thread->pagedir, (uintptr_t)s_pte->page_number << 12);
    delete_frame_entry(s_pte->fte);
	}
  else if(s_pte->location == LOC_SWAP)
    delete_swap_table_entry(s_pte->slot_number);

	

  // Deallocate s_pte
  free(s_pte);
}

void deallocate_mmap_file (struct mmap_file *mm_file){
  struct list_elem *e;
  struct sPage_table_entry *s_pte;
  struct thread *t = thread_current();

  ASSERT ( mm_file != NULL);
  ASSERT ( t != NULL);

  // Deallocate all resources related to all s-pte in mmap table
  while(!list_empty(&mm_file->s_pte_list)){
		//printf("start for\n");
    e = list_begin(&mm_file->s_pte_list);
    s_pte = list_entry(e, struct sPage_table_entry, mmap_table_elem);
    if(s_pte->location == LOC_PHYS){  
      // write back frame data into the file if the frame is dirty    
      mmap_write_back (s_pte);
      // deallocate physical memory and update page table
      palloc_free_page((uintptr_t)s_pte->fte->frame_number << 12);
	    pagedir_clear_page(s_pte->fte->thread->pagedir, (uintptr_t)s_pte->page_number << 12);

      // deallocate corresponding frame entry
      delete_frame_entry(s_pte->fte);
    }

    // deallocate s_pte
    list_remove(e);
    hash_delete (&t->sPage_table, &s_pte->elem);
    free(s_pte);

		//printf("4\n");
  }
	//printf("1\n");

  // deallocate mmap_file
  lock_acquire(&file_lock);
	//printf("1\n");
  file_close(mm_file->file);
	//printf("1\n");
  lock_release(&file_lock);

	//printf("5\n");
  
  list_remove(&mm_file->elem);
	//printf("6\n");
  free(mm_file);
}

void pin_buffer(void *buffer, size_t read_bytes){
  struct sPage_table_entry *s_pte;
  struct frame_table *fte;
  void *end = (uintptr_t)buffer + read_bytes;
  int n = PG_NUM(end) - PG_NUM(buffer) + 1;
  int i;

  for(i = 0; i < n; i++){
    s_pte = find_s_pte((uintptr_t)buffer + i * PGSIZE);
		if(s_pte == NULL)
			Exit(-1);

		if(s_pte->location == LOC_PHYS){
			s_pte->fte->pin = true;
			continue;

			NOT_REACHED();
		}

    // Check whether free physical memory space remained 
    fte = frame_alloc();
    if(fte == NULL)
      Exit(-1);

	  //printf("finish eviction!\n");
	  //printf("type %d, loc %d\n", s_pte->type, s_pte->location);

    switch(s_pte->location){      // Devide cases into where the Memory data's location is
      case LOC_NONE:
        if(s_pte->type == TYPE_STACK){
				 		//printf("before stack growth\n");
          if(!stack_growth(s_pte, fte))
            Exit(-1);
						//printf("come back from stack grow\n");

          break;
        }
      case LOC_FILE:
         //printf("before load_file!\n");
        if(!load_files(s_pte, fte))
          Exit(-1);
        break;
      case LOC_SWAP:
					//printf("before swap_in!\n");
        if(!swap_in(s_pte, fte))
          Exit(-1);
        break;      
      default:
	   		break;
    }
    s_pte->fte->pin = true;
		//printf("pin %p by %s %d\n", s_pte->page_number, thread_current()->name, thread_current()->tid);
  }
}

void unpin_buffer(void *buffer, size_t read_bytes){
  struct sPage_table_entry *s_pte;
  void *end = (uintptr_t)buffer + read_bytes;
  int n = PG_NUM(end) - PG_NUM(buffer) + 1;
  int i;

  for(i = 0; i < n; i++){
    s_pte = find_s_pte((uintptr_t)buffer + i * PGSIZE);
    ASSERT (s_pte != NULL);
		ASSERT (s_pte->fte != NULL);
    
    s_pte->fte->pin = false;
  }
}
