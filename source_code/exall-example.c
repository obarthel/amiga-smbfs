/* an example of how to use ExAll */

/*
 * Updated with a set of test features which exercise the
 * various options of ExAll():
 *
 * - Set the size of the buffer, e.g. BUFFER=500 (default
 *   is BUFFER=4096).
 *
 * - Select which type of information should be retrieved,
 *   e.g. TYPE=NAME (default is TYPE=OWNER). Possible choices
 *   are NAME, TYPE, SIZE, PROTECTION, DATE, COMMENT and
 *   OWNER.
 *
 * - Limit the number of directory entries to retrieve, e.g.
 *   MAXENTRIES=10 (no limit is set by default). This feature
 *   requires Kickstart 3.0 or better to work.
 *
 * Hit [Ctrl]+C to stop reading directory entries or use the
 * shell "Break" command.
 */

#include <exec/types.h>
#include <exec/ports.h>
#include <exec/memory.h>

#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/dosasl.h>
#include <dos/exall.h>

#if defined (__GNUC__)
#if defined (__amigaos4__)
#include <dos/obsolete.h>
#endif /* __amigaos4__ */

#include <proto/exec.h>
#include <proto/dos.h>
#else
extern struct Library *SysBase;
extern struct Library *DOSBase;

#include <pragmas/exec_pragmas.h>
#include <pragmas/dos_pragmas.h>

#include <clib/exec_protos.h>
#include <clib/dos_protos.h>
#endif /* __GNUC__ */

#include <string.h>
#include <ctype.h>

#define BUFFSIZE 4096

int
main(int argc,char *argv[])
{
	struct
	{
		STRPTR	Name;
		STRPTR	Pattern;
		LONG *	BufferSize;
		STRPTR	Type;
		LONG *	MaxEntries;
	} args;

	struct RDArgs * rda;
	BPTR obj_lock;
	LONG res2, more;
	struct ExAllData *buffer = NULL;
	struct ExAllData *ead;
	struct ExAllControl *control = NULL;
	LONG rc = RETURN_ERROR;
	char pattern[256];
	ULONG total_num_entries = 0;
	int max_entries = 0;
	int buffer_size = 0;
	int type;
	int i;

	memset(&args,0,sizeof(args));

	rda = ReadArgs("NAME/A,PATTERN/K,BUF=BUFFER/K/N,TYPE/K,MAXENTRIES/K/N", (LONG *)&args, NULL);
	if (rda == NULL)
	{
		PrintFault(IoErr(),FilePart(argv[0]));
		goto cleanup;
	}

	if (args.BufferSize != NULL)
		buffer_size = (*args.BufferSize);
	else
		buffer_size = BUFFSIZE;

	if (args.Type != NULL)
	{
		char key[16]; /* Enough for "protection". */
		int c;

		for (i = 0 ; i < (int)sizeof(key)-1 ; i++)
		{
			c = args.Type[i];
			if(c == '\0')
				break;

			key[i] = tolower(c);
		}

		key[i] = '\0';

		if (strcmp(key,"name") == 0)
		{
			type = ED_NAME;
		}
		else if (strcmp(key,"type") == 0)
		{
			type = ED_TYPE;
		}
		else if (strcmp(key,"size") == 0)
		{
			type = ED_SIZE;
		}
		else if (strcmp(key,"protection") == 0)
		{
			type = ED_PROTECTION;
		}
		else if (strcmp(key,"date") == 0)
		{
			type = ED_DATE;
		}
		else if (strcmp(key,"comment") == 0)
		{
			type = ED_COMMENT;
		}
		else if (strcmp(key,"owner") == 0)
		{
			type = ED_OWNER;
		}
		else
		{
			Printf("Type \"%s\" not known.\n", args.Type);
			goto cleanup;
		}
	}
	else
	{
		type = ED_OWNER;
	}

	if (args.MaxEntries != NULL)
	{
		if(DOSBase->lib_Version < 39)
		{
			Printf("Ignoring MAXENTRIES=%ld (dos.library V39 or better required)\n",(*args.MaxEntries));
		}
		else
		{
			if((*args.MaxEntries) < 1)
			{
				PutStr("MAXENTRIES must be > 0\n");
				goto cleanup;
			}

			max_entries = (*args.MaxEntries);
		}
	}

	/* control MUST be allocated by AllocDosObject! */
	control = (struct ExAllControl *) AllocDosObject(DOS_EXALLCONTROL, NULL);
	buffer = (struct ExAllData *) AllocMem(buffer_size, MEMF_PUBLIC|MEMF_CLEAR);

	/* always check allocations! */
	if (control == NULL || buffer == NULL)
		goto cleanup;

	if (args.Pattern != NULL)
	{
		/* parse the pattern for eac_MatchString */
		if (ParsePatternNoCase(args.Pattern, pattern, sizeof(pattern)) == -1)
		{
			PrintFault(IoErr(), args.Pattern);
			goto cleanup;
		}

		control->eac_MatchString = pattern;
	}

	/* lock the directory */
	obj_lock = Lock(args.Name, SHARED_LOCK);
	if (obj_lock == (BPTR)NULL)
	{
		PrintFault(IoErr(), args.Name);
		goto cleanup;
	}

	control->eac_LastKey = 0;	/* paranoia */

	Printf("Buffer size = %ld bytes\n", buffer_size);

	do /* while more */
	{
		if(CheckSignal(SIGBREAKF_CTRL_C))
		{
			PrintFault(ERROR_BREAK, argv[0]);

			rc = RETURN_WARN;
			break;
		}

		more = ExAll(obj_lock, buffer, buffer_size, type, control);
		res2 = IoErr();

		/* Workaround for V37 ROM/disk filesystem bug. */
		if(!more && res2 == ERROR_BAD_NUMBER && type == ED_OWNER)
		{
			type = ED_COMMENT;

			more = ExAll(obj_lock, buffer, buffer_size, type, control);
			res2 = IoErr();
		}

		if (!more && res2 != ERROR_NO_MORE_ENTRIES)
		{
			Printf("Abnormal exit, error = %ld\n",res2);
			break;
		}

		if (control->eac_Entries == 0)
		{
			/* ExAll failed normally with no entries. 'more' is usually FALSE. */
			Printf("\nReturned 0 entries (more=%s); retrying...\n", more ? "TRUE" : "FALSE");
			continue;
		}

		Printf("\nReturned %ld entries:\n",control->eac_Entries);

		for(ead = buffer ; ead != NULL ; ead = ead->ed_Next)
		{
			if(CheckSignal(SIGBREAKF_CTRL_C))
			{
				PrintFault(ERROR_BREAK, argv[0]);

				more = FALSE;

				rc = RETURN_WARN;
				break;
			}

			Printf("%s", ead->ed_Name);

			if (type >= ED_TYPE)
			{
				if (ead->ed_Type > 0)
					PutStr(" (dir)");
				else
					PutStr(" (file)");
			}

			if (type >= ED_SIZE)
			{
				if (ead->ed_Type < 0)
					Printf(", size=%ld", ead->ed_Size);
			}

			if (type >= ED_PROTECTION)
			{
				char user_other_bits[11];
				char owner_bits[9];

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

				Printf(", protection=%s %s (0x%08lx)",
					user_other_bits, owner_bits, ead->ed_Prot);
			}

			if (type >= ED_DATE)
			{
				struct DateTime dat;
				char date[LEN_DATSTRING],time[LEN_DATSTRING];

				memset(&dat,0,sizeof(dat));

				memset(date,0,sizeof(date));
				memset(time,0,sizeof(time));

				dat.dat_Stamp.ds_Days	= ead->ed_Days;
				dat.dat_Stamp.ds_Minute	= ead->ed_Mins;
				dat.dat_Stamp.ds_Tick	= ead->ed_Ticks;
				dat.dat_Format			= FORMAT_DOS;
				dat.dat_StrDate			= date;
				dat.dat_StrTime			= time;

				DateToStr(&dat);

				Printf(", date=%s %s (%ld/%ld/%ld)",
					date, time,
					ead->ed_Days, ead->ed_Mins, ead->ed_Ticks);
			}

			if (type >= ED_COMMENT)
			{
				if(ead->ed_Comment != NULL)
					Printf(", comment=\"%s\"", ead->ed_Comment);
				else
					PutStr(", comment=NULL");
			}

			if (type == ED_OWNER)
			{
				Printf(", uid=%ld, gid=%ld",
					ead->ed_OwnerUID,
					ead->ed_OwnerGID);
			}

			PutStr("\n");

			total_num_entries++;

			/* Check if we reached the limit of how many directory
			 * entries we may display.
			 */
			if(max_entries > 0)
			{
				max_entries--;
				if(max_entries == 0)
				{
					/* Stop reading directory entries (dos.library V39
					 * or better required.
					 */
					ExAllEnd(obj_lock, buffer, buffer_size, type, control);

					more = FALSE;
					break;
				}
			}
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
