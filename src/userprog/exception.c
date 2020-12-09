#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "userprog/syscall.h"		// SOS Implementation project 2 for using Exit()

// SOS Implementation project 3
#include "threads/palloc.h"    
#include "vm/page.h"
#include <string.h>
#include <stdlib.h>
#include "userprog/process.h"
#include "threads/pte.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "userprog/pagedir.h"
// End SOS Implementation project 3

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      Exit(-1); // SOS Implementation project 2 - user process exit with -1 status when page fault occurs

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */
  uintptr_t esp_growth;
  struct sPage_table_entry *s_pte;

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

	//printf("page_fault at %p by %s %d!\n", fault_addr, thread_current()->name, thread_current()->tid);
  
	/*printf ("Page fault at %p: %s error %s page in %s context.\n",
    fault_addr,
    not_present ? "not present" : "rights violation",
    write ? "writing" : "reading",
    ser ? "user" : "kernel");*/
		

	if(!not_present)
		Exit(-1);


	//printf("f->esp %p, fault_addr %p\n", f->esp, fault_addr);
   if((uintptr_t)f->esp >= (uintptr_t)fault_addr){
      esp_growth = (uintptr_t)f->esp - 4 * 1024;

      if((uintptr_t)PHYS_BASE - 8 * 1024 * 1024 > esp_growth)
         kill (f);
      else if(esp_growth < (uintptr_t)fault_addr){
			//	printf("make s_pte for new stack region\n");
         s_pte = (struct sPage_table_entry *)malloc(sizeof(struct sPage_table_entry));
         s_pte->type = TYPE_STACK;                                       // Initialize s_pte
         s_pte->location = LOC_NONE;                                    // Current location is in Physical memory
         s_pte->page_number = PG_NUM(fault_addr);
         s_pte->writable = true;
         s_pte->file = NULL;
         s_pte->fte = NULL;
         s_pte->offset = 0;
         s_pte->read_bytes = 0;
         s_pte->zero_bytes = PGSIZE;

         hash_insert(&thread_current()->sPage_table, &s_pte->elem);
      }
   }
	//printf("spte %p, find spte %p, is user vaddr %d\n",s_pte, find_s_pte(fault_addr), is_user_vaddr((uint8_t *)f->esp - PGSIZE));
  if((!find_s_pte(fault_addr) || !is_user_vaddr(fault_addr)) && s_pte ==NULL){
      /* To implement virtual memory, delete the rest of the function
         body, and replace it with code that brings in the page to
         which fault_addr refers. */
      printf ("Page fault at %p: %s error %s page in %s context.\n",
               fault_addr,
               not_present ? "not present" : "rights violation",
               write ? "writing" : "reading",
               user ? "user" : "kernel");
      kill (f);
  }
  
	//printf("before page_fault_handler!\n");


	if(!page_fault_handler(fault_addr, s_pte))
  	kill (f);
	

	//printf("finish page_fault() at %p by %s %d\n", fault_addr, thread_current()->name, thread_current()->tid);
}

bool check_physical_memory ();

bool page_fault_handler (void *vaddr, struct sPage_table_entry *e){
   //ASSERT (find_s_pte(vaddr) && is_user_vaddr(vaddr));
	//ASSERT (find_s_pte(vaddr))
   struct sPage_table_entry *s_pte;
   struct frame_table_entry *fte;
   bool result;

   s_pte = find_s_pte(vaddr);

	 if(!s_pte)
	 		s_pte = e;

   // Check whether free physical memory space remained 
   fte = frame_alloc();
   if(fte == NULL)
      return false;

	 //printf("finish eviction!\n");
	 //printf("type %d, loc %d\n", s_pte->type, s_pte->location);

   switch(s_pte->location){      // Devide cases into where the Memory data's location is
      case LOC_NONE:
         if(s_pte->type == TYPE_STACK){
				 		//printf("before stack growth\n");
            result = stack_growth(s_pte, fte);
						//printf("come back from stack grow\n");

            break;
         }
      case LOC_FILE:
         //printf("before load_file!\n");
         result = load_files(s_pte, fte);
         break;
      case LOC_SWAP:
					//printf("before swap_in!\n");
         result = swap_in(s_pte, fte);
         break;      
      default:
	   		break;
   }

	 //printf("finish page_fault_handler with %d\n", result);
   return result;
}

bool check_physical_memory(){                 // Check whether free physical memory space remained 
   uint8_t *check = palloc_get_page(PAL_USER);

   if(check == NULL)
      return false;
   
   palloc_free_page (check);
   return true;
}

bool load_files(struct sPage_table_entry *e, struct frame_table_entry *fte){
   bool success;
   
   ASSERT (fte != NULL);
  
   // Mapping frame in spte
   e->fte = fte;
   e->location = LOC_PHYS;       // Store Memory in Physcial memory
   
   // Initialize fte                
   fte->s_pte = e;
   fte->thread = thread_current();
   fte->pin = false;

		//printf("kpage %p file %p\n", kpage, e->file);

   /* Load this page. */
  // if(lock_held_by_current_thread(&file_lock)){
	 		//printf("before file read at file_load by %s %d\n", thread_current()->name, thread_current()->tid);
      //success = file_read_at (e->file, kpage, e->read_bytes, e->offset) == (int) e->read_bytes;
	 		//printf("finish file read at file_load by %s %d\n", thread_current()->name, thread_current()->tid);
/*		}
   else{
			//printf("3\n");
			//if(file_lock.holder)
				//printf("%s\n", file_lock.holder->name);
	 		//printf("before file read at file_load by %s %d\n", thread_current()->name, thread_current()->tid);*/
      lock_acquire(&file_lock);   
      success = file_read_at (e->file, (uintptr_t)fte->frame_number << 12, e->read_bytes, e->offset) == (int) e->read_bytes;
      lock_release(&file_lock);
	 		/*printf("finish file read at file_load by %s %d\n", thread_current()->name, thread_current()->tid);
   }
*/
		//printf("4\n");
   if (!success)
   {
      palloc_free_page ((uintptr_t)fte->frame_number << 12);
      free(fte);
      return false; 
   }
		//printf("3\n");
   memset ((uintptr_t)fte->frame_number << 12 + e->read_bytes, 0, e->zero_bytes);

		//printf("5\n");

   /* Add the page to the process's address space. */
   if (!install_page (((uintptr_t)e->page_number << 12), (uintptr_t)fte->frame_number << 12, e->writable)) 
   {
	 	printf("fail unistall!\n");
      palloc_free_page ((uintptr_t)fte->frame_number << 12);
      free(fte);
      return false; 
   }

		//printf("6\n");
		
		//printf("load executable before insert_frame\n");
   insert_frame(fte);     // Insert new frame table entry into frame_table
		//printf("executable load with page number %x, frame number %x\n", e->page_number, kpage);

   return true;   
}

bool stack_growth(struct sPage_table_entry *s_pte, struct frame_table_entry *fte){
   ASSERT (s_pte != NULL);
   ASSERT (fte != NULL);
   bool success;


	//printf("before install page\n");
   success = install_page ((uintptr_t)s_pte->page_number << 12, (uintptr_t)fte->frame_number << 12, true);
	//printf("after install page\n");
   if(success){
	 		//printf("install page success!\n");
      s_pte->fte = fte;
      s_pte->location = LOC_PHYS;   
                     
      fte->s_pte = s_pte;                                   // Initialize fte
      fte->thread = thread_current();
      fte->pin = false;

      insert_frame(fte);                                     // Insert fte into frame_table
   }
   else{
	 		//printf("deallocate resources\n");
      palloc_free_page ((uintptr_t)fte->frame_number << 12);
      free(fte);
      return false;
   }  

   return true;
}

