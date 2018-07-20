/* an example of how to use ExAll */

#include <exec/types.h>
#include <exec/ports.h>
#include <exec/memory.h>

#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/exall.h>

#if defined (__amigaos4__)
#include <dos/obsolete.h>

#include <proto/exec.h>
#include <proto/dos.h>
#else
extern struct Library *SysBase;
extern struct Library *DOSBase;

#include <pragmas/exec_pragmas.h>
#include <pragmas/dos_pragmas.h>

#include <clib/exec_protos.h>
#include <clib/dos_protos.h>
#endif /* __amigaos4__ */

#include <string.h>

#define BUFFSIZE 4096

int
main(int argc,char *argv[])
{
	struct
	{
		STRPTR	Name;
		STRPTR	Pattern;
		LONG *	BufferSize;
	} args;

	struct RDArgs * rda;
	BPTR obj_lock;
	LONG res2,more;
	struct ExAllData *buffer = NULL;
	struct ExAllData *ead;
	struct ExAllControl *control = NULL;
	LONG rc = RETURN_ERROR;
	char pattern[256];
	char user_other_bits[11];
	char owner_bits[9];
	struct DateTime dat;
	char date[LEN_DATSTRING],time[LEN_DATSTRING];
	ULONG total_num_entries = 0;
	int buffer_size = 0;
	int type;
	int i;

	memset(&args,0,sizeof(args));

	rda = ReadArgs("NAME/A,PATTERN/K,BUF=BUFFER/K/N",(LONG *)&args,NULL);
	if(rda == NULL)
	{
		PrintFault(IoErr(),FilePart(argv[0]));
		goto cleanup;
	}

	if(args.BufferSize != NULL)
		buffer_size = (*args.BufferSize);
	else
		buffer_size = BUFFSIZE;

	/* control MUST be allocated by AllocDosObject! */
	control = (struct ExAllControl *) AllocDosObject(DOS_EXALLCONTROL,NULL);
	buffer = (struct ExAllData *) AllocMem(buffer_size,MEMF_PUBLIC|MEMF_CLEAR);

	/* always check allocations! */
	if (control == NULL || buffer == NULL)
		goto cleanup;

	if (args.Pattern != NULL)
	{
		/* parse the pattern for eac_MatchString */
		if (ParsePatternNoCase(args.Pattern,pattern,sizeof(pattern)) == -1)
		{
			PrintFault(IoErr(), args.Pattern);
			goto cleanup;
		}

		control->eac_MatchString = pattern;
	}

	/* lock the directory */
	obj_lock = Lock(args.Name,SHARED_LOCK);
	if (obj_lock == (BPTR)NULL)
	{
		PrintFault(IoErr(), args.Name);
		goto cleanup;
	}

	control->eac_LastKey = 0;	/* paranoia */

	/* Workaround for V37 ROM/disk filesystem bug. */
	type = ED_OWNER;

	Printf("Buffer size = %ld bytes\n", buffer_size);

	do /* while more */
	{
		more = ExAll(obj_lock,buffer,buffer_size,type,control);
		res2 = IoErr();

		/* Workaround for V37 ROM/disk filesystem bug. */
		if(!more && res2 == ERROR_BAD_NUMBER && type == ED_OWNER)
		{
			type = ED_COMMENT;

			more = ExAll(obj_lock,buffer,buffer_size,type,control);
			res2 = IoErr();
		}

		if (!more && res2 != ERROR_NO_MORE_ENTRIES)
		{
			Printf("Abnormal exit, error = %ld\n",res2);
			break;
		}

		Printf("Returned %ld entries:\n\n",control->eac_Entries);

		if (control->eac_Entries == 0)
			continue;

		for(ead = buffer ; ead != NULL ; ead = ead->ed_Next)
		{
			if (ead->ed_Type > 0)
				Printf("%s (dir)", ead->ed_Name);
			else
				Printf("%s (file), size=%ld", ead->ed_Name, ead->ed_Size);

			strcpy(user_other_bits, "rwed rwed");

			for(i = 8 ; i < 16 ; i++)
			{
				if((ead->ed_Prot & (1 << i)) == 0)
				{
					int offset;

					if(i < 12)
						offset = 12 - i;
					else
						offset = 21 - i;

					user_other_bits[offset - 1] = '-';
				}
			}

			strcpy(owner_bits, "hsparwed");

			for(i = 0 ; i < 4 ; i++)
			{
				if((ead->ed_Prot & (1 << i)) != 0)
					owner_bits[7 - i] = '-';
			}

			for(i = 4 ; i < 8 ; i++)
			{
				if((ead->ed_Prot & (1 << i)) == 0)
					owner_bits[7 - i] = '-';
			}

			memset(&dat,0,sizeof(dat));

			memset(date,0,sizeof(date));
			memset(time,0,sizeof(time));

			dat.dat_Stamp.ds_Days	= ead->ed_Days;
			dat.dat_Stamp.ds_Minute	= ead->ed_Mins;
			dat.dat_Stamp.ds_Tick	= ead->ed_Ticks;
			dat.dat_Format			= FORMAT_DEF;
			dat.dat_StrDate			= date;
			dat.dat_StrTime			= time;

			DateToStr(&dat);

			Printf(", protection=%s %s (0x%08lx), date=%s %s (%ld/%ld/%ld), comment=\"%s\"",
				user_other_bits,owner_bits,ead->ed_Prot,
				date,time,
				ead->ed_Days,ead->ed_Mins,ead->ed_Ticks,
				ead->ed_Comment ? ead->ed_Comment : (STRPTR)"");

			if (type == ED_OWNER)
			{
				Printf(", uid=%ld, gid=%ld",
					ead->ed_OwnerUID,
					ead->ed_OwnerGID);
			}

			Printf("\n");

			total_num_entries++;
		}
	}
	while (more);

	UnLock(obj_lock);

	Printf("Total number of entries = %lu\n", total_num_entries);

 cleanup:

	if (rda != NULL)
		FreeArgs(rda);

	if (buffer != NULL)
		FreeMem(buffer, buffer_size);

	if (control != NULL)
		FreeDosObject(DOS_EXALLCONTROL, control);

	return(rc);
}
