#include "stdafx.h"

#define MAINPROG
#include "Disasm/disasm.h"
#include "EFormat.h"
#include "PEBuilder.h"
#include "ERebuilder.h"

#include "StringTable.h"
#include "StringFileInfo.h"
#include "VersionInfoHelperStructures.h"
#include "VersionInfoBuffer.h"
#include "VersionInfo.h"
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"user32.lib")


extern char szInputName[MAX_PATH];
extern char szOutputName[MAX_PATH];


typedef struct EXEDataInfo
{
	DWORD pEKrnlnName;
	DWORD pEInstallReg;
	DWORD pEErrorMsg;
	DWORD pEErrorTitle;
	DWORD pEStrPath;
	DWORD pEStrGetNewSock;
}EXEDataInfo;


extern "C" DWORD __stdcall GetEXECodeLength();
extern "C" DWORD __stdcall GetEXECodeStartAddress();
extern "C" DWORD __stdcall GetExeInfoAddress();
extern "C" DWORD __stdcall GetExeInfoLength();
extern "C" VOID __stdcall GetExeInfoItem(EXEDataInfo* Info);



typedef struct DllDataInfo
{
	DWORD pg_hModuleInst;
	DWORD pg_hKrnlnModule;
	DWORD pg_pNewSockPtr;
	DWORD pb_bLoadIndex;
	DWORD pg_pEDllUnload;
	DWORD pszKrnlnFnr;
	DWORD pszELanguageInstall;
	DWORD pszErrorTitle;
	DWORD pszErrorText;
	DWORD pszPathText;
	DWORD pszDllGetNewSock;
}DllDataInfo;

extern "C" DWORD __stdcall GetDllInfoLength();
extern "C" VOID __stdcall GetDllDataInfo(__out DllDataInfo* DataInfo);
extern "C" VOID __stdcall MyEDllMain(DWORD hInst,DWORD dwReason,DWORD Reserved);
extern "C" DWORD __stdcall GetDllCodeLength();
extern "C" BYTE* __stdcall DllGetDataBegin();
ImportThunk ImportList_EXE[] = 
{
	{"KERNEL32.DLL","lstrcatA"},
	{"KERNEL32.DLL","lstrlenA"},
	{"KERNEL32.DLL","LoadLibraryA"},
	{"KERNEL32.DLL","GetProcAddress"},
	{"KERNEL32.DLL","FreeLibrary"},
	{"KERNEL32.DLL","ExitProcess"},
	{"KERNEL32.DLL","GetModuleFileNameA"},
	{"USER32.DLL",	"MessageBoxA"},
	{"ADVAPI32.DLL","RegQueryValueExA"},
	{"ADVAPI32.DLL","RegCloseKey"},
	{"ADVAPI32.DLL","RegOpenKeyExA"}
};

ImportThunk ImportList_DLL[] = 
{
	{"KERNEL32.DLL","lstrcatA"},
	{"KERNEL32.DLL","lstrlenA"},
	{"KERNEL32.DLL","LoadLibraryA"},
	{"KERNEL32.DLL","GetProcAddress"},
	{"KERNEL32.DLL","FreeLibrary"},
	{"KERNEL32.DLL","GetModuleFileNameA"},
	{"USER32.DLL","MessageBoxA"},
	{"ADVAPI32.DLL","RegQueryValueExA"},
	{"ADVAPI32.DLL","RegCloseKey"},
	{"ADVAPI32.DLL","RegOpenKeyExA"}
};

string EStartupAPI_EXE[] = 
{
	"GetModuleFileNameA",
	"lstrcatA",
	"LoadLibraryA",
	"RegOpenKeyExA",
	"RegQueryValueExA",
	"RegCloseKey",
	"lstrlenA",
	"lstrcatA",
	"LoadLibraryA",
	"GetProcAddress",
	"ExitProcess",
	"FreeLibrary",
	"MessageBoxA"
};

string EStartupDll_EXE[] = 
{
	"KERNEL32.DLL",
	"KERNEL32.DLL",
	"KERNEL32.DLL",
	"ADVAPI32.DLL",
	"ADVAPI32.DLL",
	"ADVAPI32.DLL",
	"KERNEL32.DLL",
	"KERNEL32.DLL",
	"KERNEL32.DLL",
	"KERNEL32.DLL",
	"KERNEL32.DLL",
	"KERNEL32.DLL",
	"USER32.DLL"
};

string g_NormalAPI[] = {"KERNEL32.DLL","USER32.DLL","GDI32.DLL","NTDLL.DLL","MSVCRT.DLL","ADVAPI32.DLL"};

DWORD FindAPIBySystemDll(string APIName)
{
	
	for(DWORD i=0;i<ARRAYSIZE(g_NormalAPI);i++)
	{
		HMODULE hModule = LoadLibraryA(g_NormalAPI[i].c_str());
		if(hModule)
		{
			if(GetProcAddress(hModule,APIName.c_str()) != NULL)
			{
				FreeLibrary(hModule);
				return i;
			}
			FreeLibrary(hModule);
		}
	}
	return -1;
}
/*rva 到 raw 的转换*/

DWORD rva2raw(WORD nSections, PIMAGE_SECTION_HEADER pSectionHeader, DWORD rva)
{
	for(int i = nSections-1; i >= 0; i--)
	{
		if (pSectionHeader[i].VirtualAddress <= rva)
		{
			return pSectionHeader[i].PointerToRawData + rva - pSectionHeader[i].VirtualAddress;
		}
	}
	return 0;
}


VOID ERebuilder::AddChildNode(DWORD tableAddress,PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry, int depth,int Type)
{
	if(Type == -1)
	{
		Type = pEntry->Id;
	}
	if(pEntry->DataIsDirectory)
	{
		PIMAGE_RESOURCE_DIRECTORY pDir = (PIMAGE_RESOURCE_DIRECTORY)(tableAddress + pEntry->OffsetToDirectory);
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
		for(DWORD i=0; i<(DWORD)(pDir->NumberOfNamedEntries + pDir->NumberOfIdEntries); i++)
		{
			if(depth == -1)
			{
				AddChildNode(tableAddress, pEntries + i, depth);
			}
			else
			{
				AddChildNode(tableAddress, pEntries + i, depth+1);
			}
		}
	}
	else
	{
		char szResName[256];


		PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(tableAddress + pEntry->OffsetToData);
		
		DWORD raw = rva2raw(NTHeaders->FileHeader.NumberOfSections,IMAGE_FIRST_SECTION(NTHeaders),pDataEntry->OffsetToData);

		sprintf(szResName,"Res_%X",pDataEntry->OffsetToData);
		if(Type == 16)
		{
			CVersionInfo VersionInfo;
			CVersionInfoBuffer viSaveBuf;
			

			VersionInfo.FromFile(szInputName);
			VersionInfo.Write(viSaveBuf);

			BuildBlock* ResBlock = Builder->BuildSection(szResName,viSaveBuf.GetData(),viSaveBuf.GetPosition(),SEC_RSRC);
			pDataEntry->Size = viSaveBuf.GetPosition();
		}
		else
		{
			BuildBlock* ResBlock = Builder->BuildSection(szResName,&PEImage[raw],pDataEntry->Size,SEC_RSRC);
		}
		

		

		DWORD rva = Builder->GetNameRva(szResName) - Builder->ImageBase;

		pDataEntry->OffsetToData = rva;
	}
}

VOID ERebuilder::CopyResBuf()
{
	printf("正在构建资源信息....\n");
	PIMAGE_DATA_DIRECTORY pResDataDir = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if(pResDataDir->VirtualAddress && pResDataDir->Size)
	{
		PIMAGE_RESOURCE_DIRECTORY pResDir = NULL;
		DWORD ResRaw = rva2raw(NTHeaders->FileHeader.NumberOfSections,IMAGE_FIRST_SECTION(NTHeaders),pResDataDir->VirtualAddress);
		pResDir = (PIMAGE_RESOURCE_DIRECTORY)&PEImage[ResRaw];

		Builder->BuildSection("ResourcesData",(BYTE*)pResDir,pResDataDir->Size,SEC_RSRC);
		BYTE* pData = Builder->GetNameDataMem("ResourcesData");

		pResDir = (PIMAGE_RESOURCE_DIRECTORY)pData;


		PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDir + sizeof(IMAGE_RESOURCE_DIRECTORY));

		for(DWORD i=0;i<pResDir->NumberOfIdEntries;i++)
		{
			AddChildNode( (DWORD)pResDir, &pResEntry[i], 1);
		}
	}
}
ERebuilder::ERebuilder(BYTE* ImageOfMemory,DWORD LengthOfImage)
{
	PointOfECode = NULL;
	ECodeLength = 0;
	Status = FALSE;
	IsCUI = FALSE;

	DOSHeader =  (PIMAGE_DOS_HEADER)ImageOfMemory;
	NTHeaders = (PIMAGE_NT_HEADERS)&ImageOfMemory[DOSHeader->e_lfanew];
	PIMAGE_SECTION_HEADER pSectionHeaders;
	if(DOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		if(NTHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			pSectionHeaders = IMAGE_FIRST_SECTION(NTHeaders);
			DWORD NumberOfSections = NTHeaders->FileHeader.NumberOfSections;
			//搜索E语言代码段开始位置
			for(DWORD i=0;i<NumberOfSections;i++)
			{
				if(pSectionHeaders[i].SizeOfRawData > 0)
				{
					if(*(DWORD*)&ImageOfMemory[pSectionHeaders[i].PointerToRawData] == IMAGE_E_SIGNATURE)
					{
						PEImage = ImageOfMemory;
						PELength = LengthOfImage;


						ECodeLength = pSectionHeaders[i].SizeOfRawData;
						PointOfECode = (BYTE *)malloc(ECodeLength);
						memcpy(PointOfECode,&ImageOfMemory[pSectionHeaders[i].PointerToRawData],ECodeLength);
						IsDLL = FALSE;
						if(NTHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
						{
							IsDLL = TRUE;
						}
						IsCUI = (NTHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);
						Status = TRUE;
						break;
					}
				}
			}

			
			if(Status == TRUE)
			{
				//定位原始非静态编译的导出表,计算RVA RAW为之后做准备
				PIMAGE_DATA_DIRECTORY pExportDataDirectory = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				DWORD *pNamesArray = NULL;
				WORD *pNameOrdinalsArray = NULL;
				DWORD * pFunctionArray = NULL;
				if(pExportDataDirectory->VirtualAddress && pExportDataDirectory->Size)
				{
					PIMAGE_EXPORT_DIRECTORY pExpDir = NULL;

					DWORD ExportRaw = rva2raw(NTHeaders->FileHeader.NumberOfSections,pSectionHeaders,pExportDataDirectory->VirtualAddress);

					pExpDir = (PIMAGE_EXPORT_DIRECTORY)&ImageOfMemory[ExportRaw];
					if (!pExpDir->NumberOfNames) return;
				
					pNamesArray = (DWORD*)(ImageOfMemory + rva2raw(NTHeaders->FileHeader.NumberOfSections,pSectionHeaders,pExpDir->AddressOfNames));
					pNameOrdinalsArray = (WORD*)(ImageOfMemory + rva2raw(NTHeaders->FileHeader.NumberOfSections,pSectionHeaders,pExpDir->AddressOfNameOrdinals));
					pFunctionArray = (DWORD*)(ImageOfMemory + rva2raw(NTHeaders->FileHeader.NumberOfSections,pSectionHeaders,pExpDir->AddressOfFunctions));
					for (DWORD index = 0;index < pExpDir->NumberOfNames;index ++)
					{
						char* pszCurName = (char*)&ImageOfMemory[rva2raw(NTHeaders->FileHeader.NumberOfSections,pSectionHeaders,pNamesArray[index])];
						WORD NameOrdinal = pNameOrdinalsArray[index];
						if (pExpDir->NumberOfFunctions <= NameOrdinal)
						{
							printf("无效的导出表信息\n");
							exit(0);
						}
						ExportItem Item;
						Item.szName = pszCurName;
						Item.ExportRvaOrg = pFunctionArray[NameOrdinal];
						Item.ExportRawOrg = rva2raw(NTHeaders->FileHeader.NumberOfSections,pSectionHeaders,pFunctionArray[NameOrdinal]);
						Item.OffsetOfEInfo = *(DWORD*)&ImageOfMemory[Item.ExportRawOrg + 1];
						ExportList.push_back(Item);

						printf("检索导出函数:%s\n",Item.szName.c_str());
					}
				}	
			}
			else
			{
				printf("无效的输入文件,可能不是易语言非静态编译文件!?\n");
			}
		}
	}
}


BOOL ERebuilder::IsSuccess()
{
	return Status;
}


VOID ERebuilder::GetEImport()
{
	DWORD NumberOfImport = EHeader->NumberOfDllImport;
	if(!NumberOfImport) return;

	DWORD * ImportDllPtr = (DWORD*)(PointOfECode + sizeof(E_HEADER));
	DWORD * ImportAPIPtr = (DWORD*)((PointOfECode + sizeof(E_HEADER)) + sizeof(DWORD) * NumberOfImport);
	MemorySection* pSection = GetSectionInfo("const");

	BYTE* Buffer = pSection->DataPointer;
	for(DWORD i=0;i<NumberOfImport;i++)
	{
		ImportThunk Import;
		Import.Index = i;
		char* DllName = (char*)&Buffer[ImportDllPtr[i]];
		char* APIName = (char*)&Buffer[ImportAPIPtr[i]];
		if(*DllName)
		{
			_strupr(DllName);

			if(strstr(DllName,".dll")==NULL)
			{
				DWORD IndexOfStr = FindAPIBySystemDll(APIName);
				if(IndexOfStr != -1)
				{
					Import.DllName = g_NormalAPI[IndexOfStr];
					Import.APIName = APIName;
					EImportList.push_back(Import);
					continue;
					
				}
			}


			Import.DllName = DllName;
			Import.APIName = APIName;

			printf("检索易语言导入表 DLL:%s API:%s\n",DllName,APIName);
			EImportList.push_back(Import);
		}
		else
		{
			DWORD Index = FindAPIBySystemDll(APIName);
			if(Index != -1)
			{
				Import.DllName = g_NormalAPI[Index];
				Import.APIName = APIName;

				printf("检索易语言导入表 DLL:%s API:%s\n",Import.DllName.c_str(),Import.APIName.c_str());
				EImportList.push_back(Import);
				continue;
			}

			Import.DllName = DllName;
			Import.APIName = APIName;

			printf("检索易语言导入表 DLL:%s API:%s\n",DllName,APIName);
			EImportList.push_back(Import);
		}
	}
}

VOID ERebuilder::FixupExportAddress(PE_SECTION_HEADER SectionThunk)
{
	//PointOfECode

	for(DWORD i = 0; i<  ExportList.size();i++)
	{
		DWORD AddressFirst = (DWORD)&PointOfECode[ExportList[i].OffsetOfEInfo];
		DWORD AddressNext = (DWORD)((BYTE*)SectionThunk + SectionThunk->Info.OffsetOfData);
		DWORD OffsetOfCode = AddressFirst - AddressNext;
		ExportList[i].OffsetOfCode = OffsetOfCode;
	}
}
VOID ERebuilder::GetESection()
{
	DWORD SectionRVA = EHeader->RvaOfFirstSection;

	do
	{
		MemorySection Section;

		PE_SECTION_HEADER SectionThunk = (PE_SECTION_HEADER)&PointOfECode[SectionRVA];
		Section.Name = SectionThunk->Name;
		Section.UnknownByte = SectionThunk->Info.UnknownByte;
		Section.SizeOfRva = SectionThunk->SizeOfRva;
		Section.SizeOfRaw = SectionThunk->SizeOfRaw;
		if(Section.Name == "code")
		{
			FixupExportAddress(SectionThunk);
		}
		if( Section.SizeOfRaw > 0 )
		{
			Section.DataPointer = ((BYTE*)SectionThunk + SectionThunk->Info.OffsetOfData);
			Section.Relocation = &SectionThunk->RelocInfo;
		}
		else
		{
			Section.DataPointer = NULL;
			Section.Relocation = NULL;
		}

		ESectionList.push_back(Section);

		printf("检索易语言区段:%s\n",Section.Name.c_str());

		SectionRVA = SectionThunk->Info.NextSectionRva;
	}while(SectionRVA != -1);
}
VOID ERebuilder::CopySectionData()
{
	
	for(DWORD i=0;i<ESectionList.size();i++)
	{
		printf("正在构建区段%s信息.....\n",ESectionList[i].Name.c_str());
		if(ESectionList[i].Name == "const")
		{
			Builder->BuildSection("const",ESectionList[i].DataPointer,ESectionList[i].SizeOfRaw,SEC_DATA);	//Copy to data sec
			continue;
		}
		if(ESectionList[i].Name == "form")
		{
			Builder->BuildSection("form",ESectionList[i].DataPointer,ESectionList[i].SizeOfRaw,SEC_DATA);	//Copy to data sec
			continue;
		}
		if(ESectionList[i].Name == "help")
		{
			Builder->BuildSection("help",ESectionList[i].DataPointer,ESectionList[i].SizeOfRaw,SEC_DATA);	//Copy to data sec
			continue;
		}
		if(ESectionList[i].Name == "code")
		{
			Builder->BuildSection("code",ESectionList[i].DataPointer,ESectionList[i].SizeOfRaw,SEC_CODE);	//Copy to code sec
			continue;
		}
		if(ESectionList[i].Name == "var")
		{
			BYTE* Buffer = new BYTE[ESectionList[i].SizeOfRva];
			memset(Buffer,0,ESectionList[i].SizeOfRva);
			Builder->BuildSection("var",Buffer,ESectionList[i].SizeOfRva,SEC_DATA);	//Copy to rdata sec
			delete Buffer;
			continue;
		}
		if(ESectionList[i].Name == "@reloc1")
		{
			Builder->BuildSection("@reloc1",ESectionList[i].DataPointer,ESectionList[i].SizeOfRaw,SEC_DATA);	//Copy to data sec
			continue;
		}
	}
}

VOID ERebuilder::LoadRelocBySection(DWORD *RelocAdr,MemorySection* Section)
{
	if(!Section->Relocation) return;
	DWORD NumberOfReloc = Section->Relocation->NumberOfReloc;

	if(!NumberOfReloc) return;

	printf("正在构建区段%s重定位\n",Section->Name.c_str());
	DWORD RelocThunk = 0;
	BuildBlock* Block = Builder->GetNameBlock(Section->Name);

	Block->SetRelocCount(NumberOfReloc);

	for(DWORD i=1;i<=NumberOfReloc;i++)
	{
		RelocThunk = Section->Relocation->RelocArray[i];

		int Index = (RelocThunk & 0x7);

		RelocThunk >>= 3;
		
		Block->PointOfReloc[i - 1] = RelocThunk;

		RelocThunk += (DWORD)Builder->GetNameDataMem(Section->Name);

		DWORD AddValue = RelocAdr[Index];

		*(DWORD*)RelocThunk += AddValue;
	}
}

VOID ERebuilder::BuildSectionOffset(E_SECTION_RELOC_ADDR& RelocOffset)
{
	RelocOffset.PointOfCode = 0;
	RelocOffset.PointOfConst = 0;
	RelocOffset.PointOfHelp = 0;
	RelocOffset.PointOfVar = 0;

	RelocOffset.PointOfCode = Builder->GetNameRva("code");
	RelocOffset.PointOfConst =Builder-> GetNameRva("const");
	RelocOffset.PointOfHelp = Builder->GetNameRva("help");
	RelocOffset.PointOfVar = Builder->GetNameRva("var");
}

VOID ERebuilder::LoadRelocation()
{
	E_SECTION_RELOC_ADDR SectionRelocAddr;
	BuildSectionOffset(SectionRelocAddr);
	for(DWORD i=0;i<ESectionList.size();i++)
	{
		LoadRelocBySection((DWORD*)&SectionRelocAddr,&ESectionList[i]);
	}
}


VOID ERebuilder::GetLibInfo()
{
	ELibItem Item;
	char* LibList = (char*)&PointOfECode[sizeof(E_HEADER) + (EHeader->NumberOfDllImport * sizeof(DWORD)) * 2];

	while(*LibList != NULL)
	{
		char* pNext = LibList;
		char* pStr = pNext;
		pNext = strstr(LibList,"\x0D");
		*pNext = 0;
		pNext++;
		Item.libModule = pStr;

		pStr = pNext;
		pNext = strstr(pStr,"\x0D");
		*pNext = 0;
		pNext++;
		Item.libGUID = pStr;


		pStr = pNext;
		pNext = strstr(pStr,"\x0D");
		*pNext = 0;
		pNext++;
		Item.libmajorVersion = pStr;

		pStr = pNext;
		pNext = strstr(pStr,"\x0D");
		*pNext = 0;
		pNext++;
		Item.libminorVersion = pStr;

		Item.libChnName = pNext;

		ELibList.push_back(Item);

		LibList = pNext + strlen(pNext) + 1;

		printf("检索易语言支持库:%s\n",Item.libChnName.c_str());
	}
}

VOID ERebuilder::BuildEImportInfo(BYTE*& ImportPtr,DWORD& ImportLen)
{
	ImportLen = EHeader->NumberOfDllImport * sizeof(DWORD) * 2;
	ImportPtr = (BYTE *)malloc(ImportLen);

	memcpy(ImportPtr,PointOfECode + sizeof(E_HEADER),ImportLen);
}
VOID ERebuilder::BuildELibPtr(BYTE*& ELibPtr,DWORD& ELibLen)
{
	DWORD NumberOfLib = ELibList.size();
	char* wrtptr;
	for(DWORD i=0;i<NumberOfLib;i++)
	{
		ELibLen += ELibList[i].libModule.length() + 1;
		ELibLen += ELibList[i].libGUID.length() + 1;
		ELibLen += ELibList[i].libmajorVersion.length() + 1;
		ELibLen += ELibList[i].libminorVersion.length() + 1;
		ELibLen += ELibList[i].libChnName.length() + 1;
	}

	ELibLen++;
	ELibPtr = (BYTE*)malloc(ELibLen);
	memset(ELibPtr,0,ELibLen);
	wrtptr = (char*)ELibPtr;
	
	for(DWORD i=0;i<NumberOfLib;i++)
	{
		strcpy(wrtptr,ELibList[i].libModule.c_str());
		wrtptr += ELibList[i].libModule.length();
		*wrtptr = 0xD;
		wrtptr++;

		strcpy(wrtptr,ELibList[i].libGUID.c_str());
		wrtptr += ELibList[i].libGUID.length();
		*wrtptr = 0xD;
		wrtptr++;

		strcpy(wrtptr,ELibList[i].libmajorVersion.c_str());
		wrtptr += ELibList[i].libmajorVersion.length();
		*wrtptr = 0xD;
		wrtptr++;

		strcpy(wrtptr,ELibList[i].libminorVersion.c_str());
		wrtptr += ELibList[i].libminorVersion.length();
		*wrtptr = 0xD;
		wrtptr++;

		strcpy(wrtptr,ELibList[i].libChnName.c_str());
		wrtptr += ELibList[i].libChnName.length();
		*wrtptr = 0;
		wrtptr++;
		*wrtptr = 0;
	}
}
void ERebuilder::EBuildSection(BYTE*& ESectionPtr,DWORD& SectionLength)
{
	DWORD HeaderRva = Builder->GetNameRva("EHeader");
	DWORD HeaderOfMem = (DWORD)Builder->GetNameDataMem("EHeader");
	ESectionPtr = (BYTE*)Builder->GetNameDataMem("ESection");
	DWORD SectionRva = Builder->GetNameRva("ESection");
	PE_SECTION_HEADER pSection = (PE_SECTION_HEADER)ESectionPtr;

	DWORD NumberOfSection = ESectionList.size();

	for(DWORD i=0;i<NumberOfSection;i++)
	{
		strcpy(pSection[i].Name,ESectionList[i].Name.c_str());
		
		pSection[i].SizeOfRaw = ESectionList[i].SizeOfRaw;
		pSection[i].SizeOfRva = ESectionList[i].SizeOfRva;
		pSection[i].DataRva = Builder->GetNameRva(pSection[i].Name) - HeaderRva;

		DWORD RvaOfCurSec = SectionRva + sizeof(E_SECTION_HEADER) * i;
		
		pSection[i].Info.OffsetOfData = Builder->GetNameRva(pSection[i].Name) - RvaOfCurSec;
		pSection[i].Info.UnknownByte = ESectionList[i].UnknownByte;

		pSection[i].Info.NextSectionRva = (SectionRva + sizeof(E_SECTION_HEADER) * (i +1 ) ) - HeaderRva;
	}

	pSection[NumberOfSection-1].Info.NextSectionRva = -1;
}
DWORD ERebuilder::GetSectionIndex(string Name)
{
	DWORD Index = -1;
	for(DWORD i=0;i<ESectionList.size();i++)
	{
		if(Name == ESectionList[i].Name)
		{
			Index = i;
			break;
		}
	}

	return Index;
}
VOID ERebuilder::CreateHeader(E_HEADER*& pEHeader)
{
	DWORD RvaOfSec = Builder->GetNameRva("ESection");
	
	pEHeader->RvaOfCode = RvaOfSec + GetSectionIndex("code") * sizeof(E_SECTION_HEADER) - Builder->GetNameRva("EHeader");
	pEHeader->RvaOfHelp = RvaOfSec + GetSectionIndex("help") * sizeof(E_SECTION_HEADER) - Builder->GetNameRva("EHeader");
	pEHeader->RvaOfForm = RvaOfSec + GetSectionIndex("form") * sizeof(E_SECTION_HEADER) - Builder->GetNameRva("EHeader");
	pEHeader->RvaOfVar =  RvaOfSec + GetSectionIndex("var") * sizeof(E_SECTION_HEADER) - Builder->GetNameRva("EHeader");

	if( GetSectionIndex("const") == -1)
	{
		pEHeader->RvaOfConst = -1;
	}
	else
	{
		pEHeader->RvaOfConst =  RvaOfSec + GetSectionIndex("const") * sizeof(E_SECTION_HEADER) - Builder->GetNameRva("EHeader");
	}
	
	MemorySection * pSec = GetSectionInfo("code");
	
	pEHeader->RvaOfEntry = ((EHeader->RvaOfEntry + (DWORD)PointOfECode) - (DWORD)pSec->DataPointer) + Builder->GetNameRva("code") - Builder->GetNameRva("EHeader");
	pEHeader->RvaOfFirstSection = Builder->GetNameRva("ESection") - Builder->GetNameRva("EHeader");
}
VOID ERebuilder::BuildEHeader()
{
	BYTE* ImportPtr;
	DWORD ImportLen = 0;

	BYTE* ELibPtr = 0;
	DWORD ELibLen = 0;

	DWORD SectionLength = 0;
	BYTE * ESectionPtr = 0;

	PE_HEADER BuildHeader = (PE_HEADER)malloc(sizeof(E_HEADER));
	memset(BuildHeader,0,sizeof(E_HEADER));

	printf("正在构建易语言头文件信息...\n");
	Builder->BuildSection("EHeader",(BYTE *)BuildHeader,sizeof(E_HEADER),SEC_DATA);

	free(BuildHeader);

	BuildHeader = (PE_HEADER)Builder->GetNameDataMem("EHeader");
	BuildHeader->IsDllModule = EHeader->IsDllModule;
	memcpy(BuildHeader->Signature,EHeader->Signature,sizeof(EHeader->Signature));
	BuildHeader->UnknownDWORD1 = EHeader->UnknownDWORD1;
	BuildHeader->UnknownDWORD2 = EHeader->UnknownDWORD2;
	BuildHeader->UnknownDWORD3 = EHeader->UnknownDWORD3;

	BuildHeader->NumberOfDllImport = EHeader->NumberOfDllImport;

	BuildEImportInfo(ImportPtr,ImportLen);
	BuildELibPtr(ELibPtr,ELibLen);

	Builder->BuildSection("EImport",ImportPtr,ImportLen,SEC_DATA);
	Builder->BuildSection("ELib",ELibPtr,ELibLen,SEC_DATA);

	DWORD NumberOfSection = ESectionList.size();

	SectionLength = NumberOfSection * sizeof(E_SECTION_HEADER);

	ESectionPtr = (BYTE*)malloc(SectionLength);

	memset(ESectionPtr,0,SectionLength);

	Builder->BuildSection("ESection",ESectionPtr,SectionLength,SEC_DATA);

	free(ESectionPtr);

	ESectionPtr = Builder->GetNameDataMem("ESection");
	EBuildSection(ESectionPtr,SectionLength);

	E_HEADER *EHeaderPtr = (E_HEADER*)Builder->GetNameDataMem("EHeader");

	printf("正在创建易语言头文件信息...\n");
	CreateHeader(EHeaderPtr);
	
	
}
VOID ERebuilder::ReservedImportSize()
{
	if(EHeader->IsDllModule == FALSE)
	{
		for(DWORD i=0;i<ARRAYSIZE(ImportList_EXE);i++)
		{
			Builder->TreeImport.AddImport(ImportList_EXE[i].DllName,ImportList_EXE[i].APIName);
		}
	}
	else
	{
		for(DWORD i=0;i<ARRAYSIZE(ImportList_DLL);i++)
		{
			Builder->TreeImport.AddImport(ImportList_DLL[i].DllName,ImportList_DLL[i].APIName);
		}
	}

	for(DWORD i=0;i<EImportList.size();i++)
	{
		if(*EImportList[i].DllName.c_str())
		{
			Builder->TreeImport.AddImport(EImportList[i].DllName,EImportList[i].APIName);
		}
	}
	vector <ImportCreateThunk> ImportList = Builder->TreeImport.BuildImportCreateList();
	//保留IAT的大小
	DWORD IAT_Size = (ImportList.size() + 1) * sizeof(DWORD);
	BYTE* IAT_Ptr = new BYTE[IAT_Size];
	memset(IAT_Ptr,0,IAT_Size);
	Builder->BuildSection("IAT",IAT_Ptr,IAT_Size,SEC_DATA);
	delete IAT_Ptr;
}


VOID ERebuilder::GetECodeInformation()
{
	EHeader = (PE_HEADER)PointOfECode;
	if(EHeader->IsDllModule == TRUE)
	{
		printf("文件是一个Dll文件\n");
		Builder = new PEBuilder(0x10000000,TRUE,TRUE);
	}
	else
	{
		printf("文件是一个EXE文件\n");
		Builder = new PEBuilder(0x400000,FALSE,(IsCUI != TRUE));
	}
	BuildEStartup();
	GetLibInfo();
	GetESection();
	GetEImport();
	//先保留导入表的数据长度
	ReservedImportSize();
	
	CopySectionData();

	Builder->BuildPEImport();
	LoadRelocation();
	BuildEHeader();
	FixEStartupCallAPI();
	CopyResBuf();
	AddEExportInfo();

	FixECodeCallAPI();

}
VOID ERebuilder::FixECodeCallAPI()
{
	printf("正在修改易语言API调用为导入表方式....\n");
	BYTE* Ptr = Builder->GetNameDataMem("code");
	DWORD Length = Builder->GetNameDataSize("code");
	DWORD rva = Builder->GetNameRva("code");

	BYTE* PtrForHelp = Builder->GetNameDataMem("help");
	DWORD LengthForHelp = Builder->GetNameDataSize("help");
	DWORD RvaForHelp = Builder->GetNameRva("help");

	PE_LIB_CALL LibCallPtr = (PE_LIB_CALL)PtrForHelp;
	DWORD offset = 0;
	DWORD inst_length = 0;
	t_disasm da;
	do
	{
		DWORD CurrentAddress = rva + offset;
		inst_length = Disasm((char*)(Ptr + offset), MAXCMDSIZE, CurrentAddress, &da, DISASM_CODE);

		if((da.cmdtype & C_TYPEMASK) == C_CAL)
		{
			if((da.memtype & DEC_TYPEMASK) == DEC_UNKNOWN && inst_length == 5)
			{
				if((DWORD)Ptr > da.jmpconst && ((DWORD)Ptr + Length) > da.jmpconst)
				{
					DWORD nOffset = da.jmpconst - rva;
					if(*(WORD*)(Ptr + nOffset) == 0x25FF)
					{
						DWORD NewPtr = *(DWORD*)(Ptr + nOffset + sizeof(WORD));
						DWORD Rva2 = (DWORD)&LibCallPtr->MCallDllCmd - (DWORD)LibCallPtr + RvaForHelp;
						
						if( Rva2 == NewPtr)
						{
							DWORD ImportIndex = *(DWORD*)((Ptr + offset) - sizeof(DWORD));
							for(DWORD i=0;i<EImportList.size();i++)
							{
								if(EImportList[i].Index == ImportIndex)
								{
									DWORD ImpRva = Builder->GetImportRva(EImportList[i].DllName,EImportList[i].APIName);
									if(ImpRva)
									{
										BYTE* FillPtr = ((Ptr + offset) - sizeof(DWORD) - sizeof(BYTE)); 
										memset(FillPtr,0x90,10);

										*FillPtr = 0xE8;

										DWORD SubAddress = CurrentAddress - 5;
										*(DWORD*)(FillPtr + sizeof(BYTE)) = ImpRva - SubAddress - 5;
									}
								}
							}
							//
							//printf("1\n");
						}
					}
				}
				
			}
		}
		offset+=inst_length;
	}while(offset < Length);
}
MemorySection* ERebuilder::GetSectionInfo(string sectionName)
{
	MemorySection* Section = NULL;

	for(size_t i=0;i<ESectionList.size();i++)
	{
		if(sectionName==ESectionList[i].Name)
		{
			Section = &ESectionList[i];
		}
	}

	return Section;
}

VOID ERebuilder::BuildEStartup()
{
	printf("正在构建启动入口函数\n");
	if(EHeader->IsDllModule == FALSE)
	{
		BuildBlock* DataBlock = Builder->BuildSection("EExeData",(BYTE*) GetExeInfoAddress(),GetExeInfoLength(),SEC_DATA);
		BuildBlock* Block = Builder->BuildSection("EStartup",(BYTE*)GetEXECodeStartAddress(),GetEXECodeLength(),SEC_CODE);
	}
	else
	{
		
		BuildBlock* DataBlock = Builder->BuildSection("EDllData",(BYTE*)DllGetDataBegin(),GetDllInfoLength(),SEC_DATA);
		BuildBlock* Block = Builder->BuildSection("EStartup",(BYTE*)&MyEDllMain,GetDllCodeLength(),SEC_CODE);
	}
}

VOID ERebuilder::FixEStartupCallAPI()
{
	printf("正在设置启动入口函数相关信息\n");
	if(EHeader->IsDllModule == FALSE)
	{
		map <DWORD,ImportThunk*> ImportMap;

		for(DWORD i=0;i<ARRAYSIZE(ImportList_EXE);i++)
		{
			HMODULE hModule = LoadLibraryA(ImportList_EXE[i].DllName.c_str());
			if(hModule)
			{
				DWORD ImportAPIPtr = (DWORD)GetProcAddress(hModule,ImportList_EXE[i].APIName.c_str());

				if(ImportAPIPtr)
				{
					ImportMap[ImportAPIPtr] = &ImportList_EXE[i];
				}
			}
		}
	
		BuildBlock* DataBlock = Builder->GetNameBlock("EExeData");
		BuildBlock* Block =  Builder->GetNameBlock("EStartup");

		DWORD Rva = Builder->GetNameRva("EStartup");
		BYTE* Buf = Builder->GetNameDataMem("EStartup");
		DWORD max_size = Builder->GetNameDataSize("EStartup");
		DWORD offset = 0;

		t_disasm da;
		int inst_length;
		BYTE* pDisasm  = Buf;

		EXEDataInfo DataInfo;

		GetExeInfoItem(&DataInfo);

		DWORD* AddressList = (DWORD*)&DataInfo;
		DWORD AddressCount = sizeof(DataInfo) / sizeof(DWORD);

		DWORD DataRva = Builder->GetNameRva("EExeData");

		vector <DWORD> RelocList;
		do
		{
			DWORD CurrentAddress = (DWORD)GetEXECodeStartAddress() + offset;
			inst_length = Disasm((char*)(pDisasm + offset), MAXCMDSIZE, CurrentAddress, &da, DISASM_CODE);
			//FIX RELOC

			if((da.cmdtype & C_TYPEMASK) == C_PSH)
			{
				if((da.memtype & DEC_TYPEMASK) == DEC_UNKNOWN && inst_length == 5)
				{
					if(da.immconst == 0x12345678)
					{
						DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
						*pOffset = Builder->GetNameRva("EHeader");
						RelocList.push_back(offset+ da.fixupoffset);
					}

					for(DWORD i=0;i<AddressCount;i++)
					{
						if(AddressList[i] == da.immconst)
						{
							RelocList.push_back(offset+ da.fixupoffset);
							DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
							*pOffset = da.immconst - (DWORD)GetExeInfoAddress() + DataRva;
							break;
						}
					}
				}
			}
			if((da.cmdtype & C_TYPEMASK) == C_CMD)
			{
				if((da.memtype & DEC_TYPEMASK) == DEC_DWORD || (da.memtype & DEC_TYPEMASK) == DEC_UNKNOWN)
				{
					for(DWORD i=0;i<AddressCount;i++)
					{
						if(AddressList[i] == da.immconst)
						{
							RelocList.push_back(offset+ da.fixupoffset);
							DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
							*pOffset = da.immconst - (DWORD)GetExeInfoAddress() + DataRva;
							break;
						}

						if(AddressList[i] == da.adrconst)
						{
							RelocList.push_back(offset+ da.fixupoffset);
							DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
							*pOffset = da.adrconst - (DWORD)GetExeInfoAddress() + DataRva;
							break;
						}
					}	
				}
			}

			if((da.cmdtype & C_TYPEMASK) == C_CAL)
			{
				
				if((da.memtype & DEC_TYPEMASK) == DEC_UNKNOWN && inst_length == 5)
				{
					if(IsBadCodePtr((FARPROC)da.jmpconst) == FALSE)
					{
						if(*(BYTE*)da.jmpconst == 0xFF && *(BYTE*)(da.jmpconst + 1) == 0x25)
						{
							DWORD ImportPtr = **(DWORD**)(da.jmpconst + 2);
							map <DWORD,ImportThunk*>::iterator Iter;

							Iter = ImportMap.find(ImportPtr);
							if(Iter != ImportMap.end())
							{
								DWORD CurrentAddress2 = Rva + offset;
								DWORD* pOffset = (DWORD*)((pDisasm + offset) + 1);
								DWORD rva = Builder->GetImportRva(Iter->second->DllName,Iter->second->APIName);
								*pOffset = rva - CurrentAddress2 - 5;
							}
						}
					}
				}
			}
			offset+=inst_length;
		}while(offset < max_size);

		Block->SetRelocCount(RelocList.size());
		for(DWORD i=0;i<RelocList.size();i++)
		{
			Block->PointOfReloc[i] = RelocList[i];
		}
	}
	else
	{
		map <DWORD,ImportThunk*> ImportMap;

		for(DWORD i=0;i<ARRAYSIZE(ImportList_DLL);i++)
		{
			HMODULE hModule = LoadLibraryA(ImportList_DLL[i].DllName.c_str());
			if(hModule)
			{
				DWORD ImportAPIPtr = (DWORD)GetProcAddress(hModule,ImportList_DLL[i].APIName.c_str());

				if(ImportAPIPtr)
				{
					ImportMap[ImportAPIPtr] = &ImportList_DLL[i];
				}
			}
		}

		DllDataInfo DataInfo;
		GetDllDataInfo(&DataInfo);
		BuildBlock* DataBlock = Builder->GetNameBlock("EDllData");
		BuildBlock* Block =  Builder->GetNameBlock("EStartup");

		DWORD Rva = Builder->GetNameRva("EStartup");
		BYTE* Buf = Builder->GetNameDataMem("EStartup");
		DWORD max_size = Builder->GetNameDataSize("EStartup");
		DWORD offset = 0;

		t_disasm da;
		int inst_length;
		BYTE* pDisasm  = Buf;


		DWORD* AddressList = (DWORD*)&DataInfo;
		DWORD AddressCount = sizeof(DataInfo) / sizeof(DWORD);

		DWORD DataRva = Builder->GetNameRva("EDllData");

		vector <DWORD> RelocList;
		do
		{
			DWORD CurrentAddress = (DWORD)&MyEDllMain + offset;
			inst_length = Disasm((char*)(pDisasm + offset), MAXCMDSIZE, CurrentAddress, &da, DISASM_CODE);
			//FIX RELOC

			if((da.cmdtype & C_TYPEMASK) == C_PSH)
			{
				if((da.memtype & DEC_TYPEMASK) == DEC_UNKNOWN && inst_length == 5)
				{
					if(da.immconst == 0x12345678)
					{
						DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
						*pOffset = Builder->GetNameRva("EHeader");
						RelocList.push_back(offset+ da.fixupoffset);
						//Block->PointOfReloc[Block->NumberOfReloc - 1] = offset + da.fixupoffset;
					}

					for(DWORD i=0;i<AddressCount;i++)
					{
						if(AddressList[i] == da.immconst)
						{
							RelocList.push_back(offset+ da.fixupoffset);
							DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
							*pOffset = da.immconst - (DWORD)DllGetDataBegin() + DataRva;
							break;
						}
					}
				}
			}
			if((da.cmdtype & C_TYPEMASK) == C_CMD)
			{
				if((da.memtype & DEC_TYPEMASK) == DEC_DWORD || (da.memtype & DEC_TYPEMASK) == DEC_UNKNOWN)
				{
					for(DWORD i=0;i<AddressCount;i++)
					{
						if(AddressList[i] == da.immconst)
						{
							RelocList.push_back(offset+ da.fixupoffset);
							DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
							*pOffset = da.immconst - (DWORD)DllGetDataBegin() + DataRva;
							break;
						}

						if(AddressList[i] == da.adrconst)
						{
							RelocList.push_back(offset+ da.fixupoffset);
							DWORD* pOffset = (DWORD*)((pDisasm + offset) + da.fixupoffset);
							*pOffset = da.adrconst - (DWORD)DllGetDataBegin() + DataRva;
							break;
						}
					}	
				}
			}

			if((da.cmdtype & C_TYPEMASK) == C_CAL)
			{
				
				if((da.memtype & DEC_TYPEMASK) == DEC_UNKNOWN && inst_length == 5)
				{
					if(IsBadCodePtr((FARPROC)da.jmpconst) == FALSE)
					{
						if(*(BYTE*)da.jmpconst == 0xFF && *(BYTE*)(da.jmpconst + 1) == 0x25)
						{
							DWORD ImportPtr = **(DWORD**)(da.jmpconst + 2);
							map <DWORD,ImportThunk*>::iterator Iter;

							Iter = ImportMap.find(ImportPtr);
							if(Iter != ImportMap.end())
							{
								DWORD CurrentAddress2 = Rva + offset;
								DWORD* pOffset = (DWORD*)((pDisasm + offset) + 1);
								DWORD rva = Builder->GetImportRva(Iter->second->DllName,Iter->second->APIName);
								*pOffset = rva - CurrentAddress2 - 5;
							}
						}
					}
					
				}
			}
			offset+=inst_length;
		}while(offset < max_size);

		Block->SetRelocCount(RelocList.size());
		for(DWORD i=0;i<RelocList.size();i++)
		{
			Block->PointOfReloc[i] = RelocList[i];
		}
	}
}

VOID ERebuilder::AddEExportInfo()
{
	printf("正在添加易语言导出函数信息.....\n");
	BuildBlock* pCodeBlock = Builder->GetNameBlock("code");
	DWORD CodeRva = Builder->GetNameRva("code");
	for(DWORD i = 0; i<  ExportList.size();i++)
	{
		Builder->AddExportFunction(ExportList[i].szName,"code",ExportList[i].OffsetOfCode + CodeRva);
	}
}