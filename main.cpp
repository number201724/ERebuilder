#include "stdafx.h"
#include "EFormat.h"
#include "PEBuilder.h"
#include "ERebuilder.h"

DWORD ImageLength;
BYTE* ImageBuffer;

ERebuilder *Rebuilder;

char szInputName[MAX_PATH];
char szOutputName[MAX_PATH];

int main(int argc,char* argv[])
{
	if(argc != 3)
	{
		printf("ERebuilder.exe InputFile OutputFile\n");
		exit(0);
	}
	strcpy(szInputName,argv[1]);
	strcpy(szOutputName,argv[2]);
	
	FILE* f = fopen(szInputName,"rb");

	if(f)
	{
		fseek(f,0,SEEK_END);
		ImageLength = ftell(f);

		ImageBuffer = (BYTE*)malloc(ImageLength);

		fseek(f,0,SEEK_SET);
		fread(ImageBuffer,1,ImageLength,f);
		fclose(f);

		Rebuilder = new ERebuilder(ImageBuffer,ImageLength);

		if(Rebuilder->IsSuccess() == TRUE)
		{
			Rebuilder->GetECodeInformation();
			if(Rebuilder->IsSuccess() != TRUE)
				exit(0);

			Rebuilder->Builder->BuildPEFormat();
		}
	}
	else
	{
		printf("无法打开易语言程序文件!\n");
	}
	return 0;
}