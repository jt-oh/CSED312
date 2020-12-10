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

static void check_stack_growth (uintptr_t, void *);

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

		
	// check stack growth
	check_stack_growth(f->esp, fault_addr);

	if(!not_present)
		kill(f);

	if(!find_s_pte(fault_addr) || !is_user_vaddr(fault_addr)){

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

   // Page Fault Handler
	if(!page_fault_handler(fault_addr))
  	   kill (f);
}

bool page_fault_handler (void *vaddr){
   struct sPage_table_entry *s_pte;
   struct frame_table_entry *fte;
   bool result;

   s_pte = find_s_pte(vaddr);
	 if(s_pte == NULL)
	 	return NULL;

   // Check whether free physical memory space remained 
   fte = frame_alloc();
   if(fte == NULL)
      return false;

   // Devide cases into where the Memory data's location is
   switch(s_pte->location){      
      case LOC_NONE:
         if(s_pte->type == TYPE_STACK){
            result = stack_growth(s_pte, fte);
            break;
         }
      case LOC_FILE:
         result = load_files(s_pte, fte);
         break;
      case LOC_SWAP:
         result = swap_in(s_pte, fte);
         break;      
      default:
				NOT_REACHED();
	   		break;
   }

   return result;
}

bool load_files(struct sPage_table_entry *s_pte, struct frame_table_entry *fte){
   bool success;
   
   ASSERT (fte != NULL);

   // read files while grapping file lock
	ASSERT( !lock_held_by_current_thread(&file_lock));
   lock_acquire(&file_lock);   
   success = file_read_at (s_pte->file, (uintptr_t)fte->frame_number << 12, s_pte->read_bytes, s_pte->offset) == (int) s_pte->read_bytes;
   lock_release(&file_lock);
	
   if (!success)
   {
      palloc_free_page ((uintptr_t)fte->frame_number << 12);
      free(fte);
      return false; 
   }

   // Store data in Physcial memory
   memset (((uintptr_t)fte->frame_number << 12) + s_pte->read_bytes, 0, s_pte->zero_bytes);

   /* Add the page to the process's address space. */
   if (!install_page (((uintptr_t)s_pte->page_number << 12), (uintptr_t)fte->frame_number << 12, s_pte->writable)) 
   {
	 	printf("fail unistall!\n");
      palloc_free_page ((uintptr_t)fte->frame_number << 12);
      free(fte);
      return false; 
   }
		
   // Mapping frame in spte
   s_pte->fte = fte;
   s_pte->location = LOC_PHYS;       
   
   // Initialize fte                
   fte->s_pte = s_pte;
   fte->thread = thread_current();
   fte->pin = false;

   // Insert new frame table entry into frame_table
   insert_frame(fte);     

   return true;   
}

bool stack_growth(struct sPage_table_entry *s_pte, struct frame_table_entry *fte){
   ASSERT (s_pte != NULL);
   ASSERT (fte != NULL);
   bool success;

   // Store data in Physcial memory
   memset (((uintptr_t)fte->frame_number << 12) + s_pte->read_bytes, 0, s_pte->zero_bytes);

   /* Add the page to the process's address space. */
   success = install_page ((uintptr_t)s_pte->page_number << 12, (uintptr_t)fte->frame_number << 12, true);
   if(!success){
      palloc_free_page ((uintptr_t)fte->frame_number << 12);
      free(fte);
      return false;                                       
   }

   // Mapping frame in spte
   s_pte->fte = fte;
   s_pte->location = LOC_PHYS;   
                  
   // Initialize fte
   fte->s_pte = s_pte;                                   
   fte->thread = thread_current();
   fte->pin = false;

   // Insert fte into frame_table
   insert_frame(fte); 

   return true;
}

static void check_stack_growth (uintptr_t esp, void *vaddr){
   uintptr_t esp_growth;
   struct sPage_table_entry *s_pte;

   if(esp >= (uintptr_t)vaddr){
      esp_growth = esp - PGSIZE;

      if((uintptr_t)PHYS_BASE - 8 * 1024 * 1024 > esp_growth)
         return;
      else if(esp_growth < (uintptr_t)vaddr){
         s_pte = (struct sPage_table_entry *)malloc(sizeof(struct sPage_table_entry));
			   if(s_pte == NULL)
			 	   return;

         // Initialize s_pte
         s_pte->type = TYPE_STACK;                                       
         s_pte->location = LOC_NONE;                                    
         s_pte->page_number = PG_NUM(vaddr);
         s_pte->writable = true;
         s_pte->file = NULL;
         s_pte->fte = NULL;
         s_pte->offset = 0;
         s_pte->read_bytes = 0;
         s_pte->zero_bytes = PGSIZE;

         hash_insert(&thread_current()->sPage_table, &s_pte->elem);
      }
   }
}