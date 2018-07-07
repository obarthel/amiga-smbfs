/* an example of how to use ExAll */

#include <exec/types.h>
#include <exec/ports.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/exall.h>
#include <dos/obsolete.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include <string.h>

/* normally you'd include pragmas here */

#define BUFFSIZE 4096

int
main(int argc,char *argv[])
{
	BPTR obj_lock;
	LONG res2,more;
	struct ExAllData *Buffer = NULL;
	struct ExAllData *ead;
	struct ExAllControl *control = NULL;
	LONG rc = RETURN_ERROR;
	char pattern[256];
	char user_other_bits[11];
	char owner_bits[9];
	struct DateTime dat;
	char date[LEN_DATSTRING],time[LEN_DATSTRING];
	int type;
	int i;

	/* ugly argument parsing */
	if(argc >= 2 && argc <= 3)
	{
		/* control MUST be allocated by AllocDosObject! */
		control = (struct ExAllControl *) AllocDosObject(DOS_EXALLCONTROL,NULL);
		Buffer = (struct ExAllData *) AllocMem(BUFFSIZE,MEMF_PUBLIC|MEMF_CLEAR);

		/* always check allocations! */
		if (control == NULL || Buffer == NULL)
			goto cleanup;

		if (argc == 3)
		{
			/* parse the pattern for eac_MatchString */
			if (ParsePatternNoCase(argv[2],pattern,sizeof(pattern)) == -1)
			{
				Printf("ParsePatternNoCase buffer overflow!\n");
				goto cleanup;
			}

			control->eac_MatchString = pattern;
		}

		/* lock the directory */
		obj_lock = Lock(argv[1],SHARED_LOCK);
		if (obj_lock != (BPTR)NULL)
		{
			control->eac_LastKey = 0;	/* paranoia */

			type = ED_OWNER;

			do /* while more */
			{
				more = ExAll(obj_lock,Buffer,BUFFSIZE,type,control);
				res2 = IoErr();

				if(!more && res2 == ERROR_BAD_NUMBER && type == ED_OWNER)
				{
					type = ED_COMMENT;

					more = ExAll(obj_lock,Buffer,BUFFSIZE,type,control);
					res2 = IoErr();
				}

				if (!more)
				{
					if(res2 != ERROR_NO_MORE_ENTRIES)
						Printf("Abnormal exit, error = %ld\n",res2);

					break;
				}

				Printf("Returned %ld entries:\n\n",control->eac_Entries);

				if (control->eac_Entries > 0)
				{
					for(ead = Buffer ; ead != NULL ; ead->ed_Next)
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

						ead = ead->ed_Next;
					}
				}

				rc = RETURN_OK;	/* success */
			}
			while (more);

			UnLock(obj_lock);
		}
		else
		{
			Printf("Couldn't find %s\n", argv[1]);
		}
	}
	else
	{
		Printf("Usage: %s dirname [pattern]\n", argv[0]);
	}

 cleanup:

	if (Buffer != NULL)
		FreeMem(Buffer,BUFFSIZE);

	if (control != NULL)
		FreeDosObject(DOS_EXALLCONTROL,control);

	return(rc);
}
