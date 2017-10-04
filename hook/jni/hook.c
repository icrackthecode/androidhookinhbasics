#include <asm/ptrace.h>
#include <asm/ptrace.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unistd.h>

#include <dirent.h>

#if defined(__i386__)
#define pt_regs user_regs_struct
#endif

#define LIB_C "/system/lib/libc.so"
#define CPSR_T_MASK (1u << 5)

int status_main = 0;

void
evil_function()
{
	//empty for now
	
}

/** Utils */

/**
 * Do a hexdump
 * @param desc simple description
 * @param addr address
 * @param len  size
 */
void
hexDump(char* desc, void* addr, int len)
{
  int i;
  unsigned char buff[17];
  unsigned char* pc = (unsigned char*)addr;

  // Output description if given.
  if (desc != NULL)
    //  printf ("%s:\n", desc);

    if (len == 0) {
      printf("  ZERO LENGTH\n");
      return;
    }
  if (len < 0) {
    printf("  NEGATIVE LENGTH: %i\n", len);
    return;
  }

  // Process every byte in the data.
  for (i = 0; i < len; i++) {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      if (i != 0)

        // Output the offset.
        printf("  %04x ", i);
    }

    // Now the hex code for the specific character.
    printf(" %02x", pc[i]);

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 64] = '.';
    else
      buff[i % 64] = pc[i];
    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    //  printf ("   ");
    i++;
  }

  // And print the final ASCII bit.
  printf("  %s\n", buff);
}

/**
 * Read data memory address
 * @param pid  target pid
 * @param src  src
 * @param size size
 */
void
ptrace_readdata(pid_t pid, uint8_t* src, size_t size)
{
  printf("%s\n", "**********************************************");

  uint32_t i, j, remain;
  uint8_t* laddr = (uint8_t*)malloc(sizeof(uint8_t));

  union u
  {
    long val;
    char chars[sizeof(long)];
  } d;

  j = size / 4;
  remain = size % 4;

  for (i = 0; i < j; i++) {
    d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
    memcpy(laddr, d.chars, 4);
    src += 4;
    laddr += 4;

    // /  printf("[+] hexdump %lx\n",d.val );
    hexDump("", &d.val, sizeof(0x100));
  }

  if (remain > 0) {
    d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
    memcpy(laddr, d.chars, remain);
    hexDump("", &d.val, sizeof(0x100));

    //  printf("[+] hexdump %lx\n",d.val );
  }

  printf("%s\n", "**********************************************");
}

/**
 * Write data into memory
 * @param pid  target pid
 * @param dest destination
 * @param data data
 * @param size size
 */
void
ptrace_writedata(pid_t pid, uint8_t* dest, uint8_t* data, size_t size)
{
  uint32_t i, j, remain;
  uint8_t* laddr;

  union u
  {
    long val;
    char chars[sizeof(long)];
  } d;

  j = size / 4;
  remain = size % 4;

  laddr = data;

  for (i = 0; i < j; i++) {
    memcpy(d.chars, laddr, 4);
    ptrace(PTRACE_POKETEXT, pid, dest, d.val);

    dest += 4;
    laddr += 4;
  }

  if (remain > 0) {
    d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
    for (i = 0; i < remain; i++) {
      d.chars[i] = *laddr++;
    }

    ptrace(PTRACE_POKETEXT, pid, dest, d.val);
  }
}

/** End of Utils */

/**
 *  This function get the process name from process id.
 * @param  process_name [name of processs]
 * @return              [process id]
 */
int
find_pid_of(const char* process_name)
{
  int id;
  pid_t pid = -1;
  DIR* dir;
  FILE* fp;
  char filename[32];
  char cmdline[256];

  struct dirent* entry;

  if (process_name == NULL)
    return -1;

  dir = opendir("/proc");
  if (dir == NULL)
    return -1;

  while ((entry = readdir(dir)) != NULL) {
    id = atoi(entry->d_name);
    if (id != 0) {
      sprintf(filename, "/proc/%d/cmdline", id);
      fp = fopen(filename, "r");
      if (fp) {
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);

        if (strcmp(process_name, cmdline) == 0) {
          /* process found */
          pid = id;
          break;
        }
      }
    }
  }

  closedir(dir);
  return pid;
}

/**
 * This functions find the loading address of the passed library
 * @param  library Library of interest
 * @param  pid     Target program id
 * @return         pointer to library loading address
 */
uintptr_t
findLoadingAddress(const char* library, pid_t pid)
{
  char pid_maps[0xFF] = { 0 }, buffer[1024] = { 0 };
  FILE* fp = NULL;
  uintptr_t address = 0;

  sprintf(pid_maps, "/proc/%d/maps", pid);
  fp = fopen(pid_maps, "rt");
  if (fp == NULL) {
    perror("[^] Unable to parse maps files");
    return -1;
  }

  while (fgets(buffer, sizeof(buffer), fp)) {
    if (strstr(buffer, library)) {
      address = (uintptr_t)strtoul(buffer, NULL, 16);
      return address;
    }
  }

  if (fp) {
    fclose(fp);
  }

  return address;
}

/**
 * This function bypasses KASLR to give address of remote function
 * @param library                [target library]
 * @param pid                    [target process id]
 * @param local_function_address [address of remote function]
 */
void*
functionAddress(const char* library, pid_t pid, void* local_function_address)
{
  uintptr_t remote_loading_address, remote_function_address,
    local_loading_address;

  local_loading_address = findLoadingAddress(library, getpid());

  remote_loading_address = findLoadingAddress(library, pid);
  remote_function_address = (uintptr_t)local_function_address +
                            (remote_loading_address - local_loading_address);

  return (void*)remote_function_address;
}

/**
 * Returns the GOT address of target function
 * @param  module_path Module holding  symbol of interest
 * @param  symbol_name symbol name
 * @param  pid         target proccess id
 * @return             address from GOT
 */
uint32_t
find_got_entry_address(const char* module_path, const char* symbol_name,
                       pid_t pid)
{
  uint32_t module_base = findLoadingAddress(module_path, pid);

  if (module_base == 0) {
    return 0;
  }

  printf("[+] base address of %s: 0x%x\n", module_path, module_base);

  int fd = open(module_path, O_RDONLY);
  if (fd == -1) {
    return 0;
  }

  Elf32_Ehdr* elf_header = (Elf32_Ehdr*)malloc(sizeof(Elf32_Ehdr));
  if (read(fd, elf_header, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
    return 0;
  }

  uint32_t sh_base = elf_header->e_shoff;
  uint32_t ndx = elf_header->e_shstrndx;
  uint32_t shstr_base = sh_base + ndx * sizeof(Elf32_Shdr);

  lseek(fd, shstr_base, SEEK_SET);
  Elf32_Shdr* shstr_shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr));
  if (read(fd, shstr_shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
    return 0;
  }

  char* shstrtab = (char*)malloc(sizeof(char) * shstr_shdr->sh_size);
  lseek(fd, shstr_shdr->sh_offset, SEEK_SET);
  if (read(fd, shstrtab, shstr_shdr->sh_size) != shstr_shdr->sh_size) {
    return 0;
  }

  Elf32_Shdr* shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr));
  Elf32_Shdr* relplt_shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr));
  Elf32_Shdr* dynsym_shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr));
  Elf32_Shdr* dynstr_shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr));

  lseek(fd, sh_base, SEEK_SET);
  if (read(fd, shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
    return 0;
  }
  int i = 1;
  char* s = NULL;
  for (; i < elf_header->e_shnum; i++) {
    s = shstrtab + shdr->sh_name;
    if (strcmp(s, ".rel.plt") == 0)
      memcpy(relplt_shdr, shdr, sizeof(Elf32_Shdr));
    else if (strcmp(s, ".dynsym") == 0)
      memcpy(dynsym_shdr, shdr, sizeof(Elf32_Shdr));
    else if (strcmp(s, ".dynstr") == 0)
      memcpy(dynstr_shdr, shdr, sizeof(Elf32_Shdr));

    if (read(fd, shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
      printf("[-] read %s error! i = %d, in %s at line %d\n", module_path, i,
             __FILE__, __LINE__);
      return 0;
    }
  }

  // read dynmaic symbol string table
  char* dynstr = (char*)malloc(sizeof(char) * dynstr_shdr->sh_size);
  lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
  if (read(fd, dynstr, dynstr_shdr->sh_size) != dynstr_shdr->sh_size) {
    printf("[-] read %s error!\n", module_path);
    return 0;
  }

  // read dynamic symbol table
  Elf32_Sym* dynsymtab = (Elf32_Sym*)malloc(dynsym_shdr->sh_size);
  lseek(fd, dynsym_shdr->sh_offset, SEEK_SET);
  if (read(fd, dynsymtab, dynsym_shdr->sh_size) != dynsym_shdr->sh_size) {
    printf("[-] read %s error!\n", module_path);
    return 0;
  }

  // read each entry of relocation table
  Elf32_Rel* rel_ent = (Elf32_Rel*)malloc(sizeof(Elf32_Rel));
  lseek(fd, relplt_shdr->sh_offset, SEEK_SET);
  if (read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel)) {
    printf("[-] read %s error!\n", module_path);
    return 0;
  }
  for (i = 0; i < relplt_shdr->sh_size / sizeof(Elf32_Rel); i++) {
    ndx = ELF32_R_SYM(rel_ent->r_info);
    if (strcmp(dynstr + dynsymtab[ndx].st_name, symbol_name) == 0) {
      printf("[+] got entry offset of %s: 0x%x\n", symbol_name,
             rel_ent->r_offset);
      break;
    }
    if (read(fd, rel_ent, sizeof(Elf32_Rel)) != sizeof(Elf32_Rel)) {
      printf("[-] read %s error!\n", module_path);
      return 0;
    }
  }

  uint32_t offset = rel_ent->r_offset;
  Elf32_Half type = elf_header->e_type; // ET_EXEC or ET_DYN

  free(elf_header);
  free(shstr_shdr);
  free(shstrtab);
  free(shdr);
  free(relplt_shdr);
  free(dynsym_shdr);
  free(dynstr_shdr);
  free(dynstr);
  free(dynsymtab);
  free(rel_ent);

  // GOT entry offset is different between ELF executables and shared libraries
  if (type == ET_EXEC)
    return offset;
  else if (type == ET_DYN)
    return offset + module_base;

  return 0;
}

/**
 * Call function in remote process
 * @param  pid           target pid
 * @param  function_addr target function address
 * @param  args          function arguments
 * @param  argc          argument count
 * @return               return address of remote function
 */
long
CallRemoteFunction(pid_t pid, long function_addr, long* args, size_t argc)
{
  struct pt_regs regs;
  // backup the original regs
  struct pt_regs backup_regs;
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  memcpy(&backup_regs, &regs, sizeof(struct pt_regs));
  // put the first 4 args to r0-r3
  int i;
  for (i = 0; i < argc && i < 4; ++i) {
    regs.uregs[i] = args[i];
  }
  // push the remainder to stack
  if (argc > 4) {
    regs.ARM_sp -= (argc - 4) * sizeof(long);
    long* data = args + 4;
    ptrace_writedata(pid, (uint8_t*)regs.ARM_sp, (uint8_t*)data,
                     (argc - 4) * sizeof(long));
  }
  // set return addr to 0, so we could catch SIGSEGV
  regs.ARM_lr = 0;
  regs.ARM_pc = function_addr;
  if (regs.ARM_pc & 1) {
    // thumb
    regs.ARM_pc &= (~1u);
    regs.ARM_cpsr |= CPSR_T_MASK;
  } else {
    // arm
    regs.ARM_cpsr &= ~CPSR_T_MASK;
  }
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  waitpid(pid, NULL, WUNTRACED);
  // to get return value;
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  ptrace(PTRACE_SETREGS, pid, NULL, &backup_regs);
  // Fuction return value

  printf("Call remote function %lx with %d arguments, return value is %lx\n",
         function_addr, argc, regs.ARM_r0);

  return regs.ARM_r0;
}

/**
 * Map memory in target VMA
 * @param  pid  Target pid
 * @return     Page start of maped area
 */
uint32_t
page_mmap(pid_t pid)
{
  void* _mmap;
  _mmap = functionAddress(LIB_C, pid, (void*)mmap);
  long params[6];
  params[0] = 0;
  params[1] = 0x400;
  params[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
  params[3] = MAP_PRIVATE | MAP_ANONYMOUS;
  params[4] = 0;
  params[5] = 0;

  return CallRemoteFunction(pid, _mmap, params, 6);
}

uintptr_t findmallocPageStart(const char *library, pid_t pid) {

  char pid_maps[0xFF] = {0}, buffer[1024] = {0};
  FILE *fp = NULL;
  uintptr_t address = 0;

  sprintf(pid_maps, "/proc/%d/maps", pid);
  fp = fopen(pid_maps, "rt");
  if (fp == NULL) {
    perror("[^] Unable to parse maps files");
    return -1;
  }

  while (fgets(buffer, sizeof(buffer), fp)) {
    if (strstr(buffer, library)) {
      if (strstr(buffer, "rw-p")) {
        address = (uintptr_t)strtoul(buffer, NULL, 16);
        return address;
      }
    }
  }

  if (fp) {
    fclose(fp);
  }

  return address;
}


/**
 * This functions finds the r-x page of the passed library
 * @param  library Library of interest
 * @param  pid     Target program id
 * @return         pointer to library loading address
 */
uintptr_t findLibcPageStart(const char *library, pid_t pid) {

  char pid_maps[0xFF] = {0}, buffer[1024] = {0};
  FILE *fp = NULL;
  uintptr_t address = 0;

  sprintf(pid_maps, "/proc/%d/maps", pid);
  fp = fopen(pid_maps, "rt");
  if (fp == NULL) {
    perror("[^] Unable to parse maps files");
    return -1;
  }

  while (fgets(buffer, sizeof(buffer), fp)) {
    if (strstr(buffer, library)) {
      if (strstr(buffer, "r-xp")) {
        address = (uintptr_t)strtoul(buffer, NULL, 16);
        return address;
      }
    }
  }

  if (fp) {
    fclose(fp);
  }

  return address;
}

void page_change_prop_malloc(pid_t pid, void *remote_function) {
  void *_mprotect, *page_start_address;
  _mprotect = functionAddress(LIB_C, pid, (void *)mprotect);

  size_t page_size = sysconf(_SC_PAGESIZE);
  int status = 0;

  page_start_address = (void *)findLibcPageStart(LIB_C, pid);
  printf("[+] Page starts @  %p\n", page_start_address);
  long params[3];

 params[0] = page_start_address;
  params[1] = page_size;
  params[2] = PROT_READ |PROT_EXEC;

  CallRemoteFunction(pid, _mprotect,params, 3);
  
}


int
main(int argc, char const* argv[])
{
  pid_t target_pid = find_pid_of("/data/local/tmp/target");
  int ptrace_ret;
  struct pt_regs original_regs, modified_regs, temp_regs;
  void* _remote_function;
  uint32_t *GOT_entry_address, *map_base;
  char* sym = "sleep";

  /**
 *1 . Attach to the process
 */

  if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
    perror("[^] Unabe to attach target");
    return -1;
  }

  wait(NULL);

  /**
 * 2. Get remote address
 */
  _remote_function = functionAddress(LIB_C, target_pid, (void*)sleep);
  printf("[+] Remote address found @ %p\n", _remote_function);

  /*
      3. Get remote GOT
 */
  GOT_entry_address = (uint32_t*)(size_t)find_got_entry_address(
    "/data/local/tmp/target", sym, target_pid);
  printf("[+] Sleep address found @ %p\n", GOT_entry_address);

  /*
      4. Map memory in target process
 */
  map_base = (uint32_t*)(size_t)page_mmap(target_pid);
  printf("[+] Map base @ %p\n", map_base);


  /*
      5. Write evil function in mapped area
 */

  ptrace_writedata(target_pid, (uint8_t *)map_base, (uint8_t *)evil_function-1,sizeof(map_base));
  ptrace_readdata(target_pid, (uint8_t *)(map_base-1), 0x20);


  /*
        6. Replace GOT pointer with pointer to evil function
 */
  if (_remote_function == (uint32_t*)(size_t)ptrace(PTRACE_PEEKDATA, target_pid, GOT_entry_address, NULL)) {
   // printf("%s\n", "[+] GOT address holds ");

  	uint32_t target_memory = (uint32_t)map_base;

  	target_memory =  target_memory+1; 

    ptrace_writedata(target_pid, (uint8_t*)GOT_entry_address, (uint8_t*)&target_memory,
                     sizeof(long));

   ptrace_readdata(target_pid, (uint8_t *)GOT_entry_address, 0x4);
    ptrace_readdata(target_pid, (uint8_t *)(map_base+1), 0x20);

  } else {
    printf("%s\n", "noooo");
  }

  ptrace(PTRACE_DETACH, &target_pid, NULL, NULL);

  return 0;
}