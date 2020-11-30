#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

// SOS Implementation
typedef int pid_t;

void push_arg_to_stack (char **, int, void **);
struct thread *get_child_process(tid_t);
void remove_child_process (struct thread *);

// End SOS Implementation

// SOS Implementation project 3
bool install_page (void *, void *, bool);

#endif /* userprog/process.h */
