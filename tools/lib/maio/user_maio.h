#ifndef   __USER_MAIO__
#define   __USER_MAIO__

//#define NR_PAGES (1536ULL)
#define NR_PAGES (256ULL)
#define HP_SIZE (1<<21)	//2MB Files
#define FILE_NAME "/mnt/huge/hugepagefile"
#define LENGTH (NR_PAGES * HP_SIZE)
#define PROTECTION (PROT_READ | PROT_WRITE)


#endif /*__USER_MAIO__*/
