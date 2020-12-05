#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "userprog/process.h"

void syscall_init (void);

// SOS Implementation project 2
void hHalt (void);
void Exit (int);
pid_t Exec(const char *);
int Wait (pid_t);
bool Create (const char *, unsigned);
bool Remove (const char *);
int Open (const char *);
int Filesize (int);
int Read (int, void *, unsigned);
int Write (int, const void *, unsigned);
void Seek (int, unsigned);
unsigned Tell (int);
void Close (int);

bool isValid_Vaddr (void *);
void pop_arg_from_stack (void *, int *, int);
int process_create_file (struct file *);
struct file *process_get_file (int);
void process_close_file (int);


// SOS Implementation project 3
typedef int mapid_t;
void mmap_write_back (struct sPage_table_entry *);
static mapid_t allocate_mapid (void);
void Munmap(mapid_t);
mapid_t Mmap(int fd, void *);
// End SOS Implementation

#endif /* userprog/syscall.h */
