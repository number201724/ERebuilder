#include "stdafx.h"
#include "PEBuilder.h"

#include <algorithm>
#include <functional>
#include "VersionInfo.h"
#pragma pack(1)
typedef struct JmpCode
{
	BYTE nix;
	BYTE code;
	DWORD Address;
}JmpCode;
#pragma pack()

extern char szInputName[MAX_PATH];
extern char szOutputName[MAX_PATH];

//一般来说够用了
#define PE_IMAGE_HEADER_SIZE 0x400

BYTE ImageDosHeaderData[] = 
{
	0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
	0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0,0x00,0x00,0x00,
	0x0E,0x1F,0xBA,0x0E,0x00,0xB4,0x09,0xCD,0x21,0xB8,0x01,0x4C,0xCD,0x21,0x54,0x68,
	0x69,0x73,0x20,0x70,0x72,0x6F,0x67,0x72,0x61,0x6D,0x20,0x63,0x61,0x6E,0x6E,0x6F,
	0x74,0x20,0x62,0x65,0x20,0x72,0x75,0x6E,0x20,0x69,0x6E,0x20,0x44,0x4F,0x53,0x20,
	0x6D,0x6F,0x64,0x65,0x2E,0x0D,0x0D,0x0A,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
BuildBlock::BuildBlock()
{
	BufferLength = 0;
	NumberOfReloc = 0;

	Buffer = (PBYTE)malloc(0);
	PointOfReloc = (PDWORD)malloc(0);
}
VOID BuildBlock::ReSize(DWORD BufSize)
{
	Buffer = (PBYTE)realloc(Buffer,BufSize);
}
VOID BuildBlock::SetRelocCount(DWORD Count)
{
	NumberOfReloc = Count;
	PointOfReloc = (PDWORD)realloc(PointOfReloc,NumberOfReloc * sizeof(DWORD));
}
BuildBlock::~BuildBlock()
{
	free(Buffer);
	free(PointOfReloc);
}

ImageSection::ImageSection()
{
	StartAddress = 0;
	EndOfRva = 0;
}
BuildBlock * ImageSection::FindName(string Name)
{
	BuildBlock* Block = NULL;
	for(DWORD i=0;i<BuildDataList.size();i++)
	{
		if(BuildDataList[i]->Name == Name)
		{
			Block = BuildDataList[i];
			break;
		}
	}
	return Block;
}
BuildBlock* ImageSection::BuildSection(CHAR* Name,BYTE* Data,DWORD Length)
{
	BuildBlock* Block = new BuildBlock();
	Block->Name = Name;
	Block->ReSize(Length);
	memcpy(Block->Buffer,Data,Length);
	Block->BufferLength = Length;
	Block->DataRVA = EndOfRva;
	EndOfRva += Length;
	BuildDataList.push_back(Block);
	return Block;
}
void PEBuilder::CalcSectionRva()
{
	SecTextBegin = NTHeaders->OptionalHeader.BaseOfCode + NTHeaders->OptionalHeader.ImageBase;
	SecDataBegin = AlignToMem(SecText.EndOfRva) + SecTextBegin;
	SecRsrcBegin = SecDataBegin + AlignToMem(SecData.EndOfRva);
	SecRelocBegin = SecRsrcBegin + AlignToMem(SecRsrc.EndOfRva);

	SecText.StartAddress = SecTextBegin;
	SecData.StartAddress = SecDataBegin;
	SecRsrc.StartAddress = SecRsrcBegin;
	SecReloc.StartAddress = SecRelocBegin;

}
DWORD PEBuilder::GetNameDataSize(string Name)
{
	BuildBlock* Block = SecText.FindName(Name);
	if(!Block)
	{
		Block = SecData.FindName(Name);
	}
	if(!Block)
	{
		Block = SecRData.FindName(Name);
	}
	if(!Block)
	{
		Block = SecRsrc.FindName(Name);
	}
	if(!Block)
	{
		Block = SecReloc.FindName(Name);
	}

	if(Block)
	{
		return Block->BufferLength;
	}
	return 0;
}
BYTE* PEBuilder::GetNameDataMem(string Name)
{
	BuildBlock* Block = SecText.FindName(Name);
	if(!Block)
	{
		Block = SecData.FindName(Name);
	}
	if(!Block)
	{
		Block = SecRData.FindName(Name);
	}
	if(!Block)
	{
		Block = SecRsrc.FindName(Name);
	}
	if(!Block)
	{
		Block = SecReloc.FindName(Name);
	}

	if(Block)
	{
		return Block->Buffer;
	}
	return 0;
}

BuildBlock* PEBuilder::GetNameBlock(string Name)
{
	BuildBlock* Block = SecText.FindName(Name);
	if(!Block)
	{
		Block = SecData.FindName(Name);
	}
	if(!Block)
	{
		Block = SecRData.FindName(Name);
	}
	if(!Block)
	{
		Block = SecRsrc.FindName(Name);
	}
	if(!Block)
	{
		Block = SecReloc.FindName(Name);
	}

	if(Block)
	{
		return Block;
	}
	return 0;
}
DWORD PEBuilder::GetNameRva(string Name)
{
	DWORD rva=0;
	BuildBlock* Block = SecText.FindName(Name);
	if(Block)
	{
		rva = Block->DataRVA + SecTextBegin;;
	}
	if(!Block)
	{
		Block = SecData.FindName(Name);
		if(Block)
			rva = Block->DataRVA + SecDataBegin;
	}
	if(!Block)
	{
		Block = SecRData.FindName(Name);
		if(Block)
			rva = Block->DataRVA + SecRDataBegin;
	}
	if(!Block)
	{
		Block = SecRsrc.FindName(Name);
		if(Block)
			rva = Block->DataRVA + SecRsrcBegin;
	}
	if(!Block)
	{
		Block = SecReloc.FindName(Name);
		if(Block)
			rva = Block->DataRVA + SecRelocBegin;
	}
	return rva;
}
BuildBlock* PEBuilder::BuildSection(CHAR* Name,BYTE* Data,DWORD Length,DWORD Block)
{
	BuildBlock* Build = NULL;
	switch(Block)
	{
	case SEC_CODE:
		Build = SecText.BuildSection(Name,Data,Length);
		break;
	case SEC_DATA:
		Build = SecData.BuildSection(Name,Data,Length);
		break;
	case SEC_RDATA:
		Build = SecData.BuildSection(Name,Data,Length);
		break;
	case SEC_RSRC:
		Build = SecRsrc.BuildSection(Name,Data,Length);
		break;
	case SEC_RELOC:
		Build = SecReloc.BuildSection(Name,Data,Length);
	default:
		assert(0);
		break;
	}

	CalcSectionRva();


	return Build;
}
string PEBuilder::GetModuleString(string ModuleName)
{
	HMODULE hModule;
	string getstr = "";
	CHAR szFileName[MAX_PATH];
	
	hModule = LoadLibraryA(ModuleName.c_str());

	if(hModule)
	{
		GetModuleFileNameA(hModule,szFileName,sizeof(szFileName));

		char*ps = strrchr(szFileName,'\\');
		if(ps)
			ps++;

		if(ps)
		{
			_strlwr(szFileName);
			getstr = ps;
		}

		FreeLibrary(hModule);
	}

	return getstr;
}
vector <ImportCreateThunk> ImportTree::BuildImportCreateList()
{
	vector <ImportCreateThunk> CreateList;

	for(map <string,vector <ImportThunk>>::iterator Iter = ImportTreeList.begin();Iter != ImportTreeList.end();Iter++)
	{
		vector <ImportThunk>& ThunkList = Iter->second;
		for(DWORD i=0;i<ThunkList.size();i++)
		{
			ImportCreateThunk ImportCreate;
			ImportCreate.DllName = ThunkList[i].DllName;
			ImportCreate.APIName = ThunkList[i].APIName;
			ImportCreate.Index = CreateList.size();
			CreateList.push_back(ImportCreate);
		}
	}
	return CreateList;
}

DWORD ImportTree::GetImportIndex(string DllName,string APIName)
{
	vector <ImportCreateThunk> ImportList = BuildImportCreateList();

	for(DWORD i=0;i<ImportList.size();i++)
	{
		if(ImportList[i].APIName == APIName && ImportList[i].DllName == DllName)
		{
			return i;
		}
	}
	return -1;
}
void ImportTree::AddImport(string DllName,string APIName)
{
	map <string,vector <ImportThunk>>::iterator Iter = ImportTreeList.find(DllName);

	if(Iter == ImportTreeList.end())
	{
		vector <ImportThunk> ThunkList;
		ImportThunk Thunk;
		Thunk.DllName = DllName;
		Thunk.APIName = APIName;
		ThunkList.push_back(Thunk);
		ImportTreeList[DllName] = ThunkList;
	}
	else
	{
		vector <ImportThunk>& ThunkList = Iter->second;
		for(DWORD i=0;i<ThunkList.size();i++)
		{
			if(ThunkList[i].APIName == APIName)
				return;
		}
		ImportThunk Thunk;
		Thunk.DllName = DllName;
		Thunk.APIName = APIName;
		ThunkList.push_back(Thunk);
	}
}

PEBuilder::~PEBuilder()
{

}

PEBuilder::PEBuilder(DWORD BaseAddr,BOOL IsDllFile,BOOL ProcGUI)
{
	ImageBase = BaseAddr;
	SecTextBegin = 0;
	SecDataBegin = 0;
	SecRDataBegin = 0;
	SecRsrcBegin = 0;
	SecRelocBegin = 0;
	ImageHeaderData = (PBYTE)malloc(0x400);
	memset(ImageHeaderData,0,0x400);
	DOSHeader = (PIMAGE_DOS_HEADER)ImageHeaderData;

	memcpy(ImageHeaderData,ImageDosHeaderData,sizeof(ImageDosHeaderData));

	NTHeaders = (PIMAGE_NT_HEADERS)&ImageHeaderData[DOSHeader->e_lfanew];
	memset(NTHeaders,0,sizeof(IMAGE_NT_HEADERS));

	NTHeaders->Signature = IMAGE_NT_SIGNATURE;
	//NTHeaders->FileHeader.NumberOfSections = 0;
	NTHeaders->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	NTHeaders->FileHeader.TimeDateStamp = 0;
	NTHeaders->FileHeader.PointerToSymbolTable = 0;

	if(IsDllFile == FALSE)
	{
		NTHeaders->FileHeader.Characteristics = 
			IMAGE_FILE_EXECUTABLE_IMAGE|
			IMAGE_FILE_32BIT_MACHINE|
			IMAGE_FILE_RELOCS_STRIPPED|
			IMAGE_FILE_LINE_NUMS_STRIPPED|
			IMAGE_FILE_LOCAL_SYMS_STRIPPED;
	}
	else
	{
		NTHeaders->FileHeader.Characteristics = 
			IMAGE_FILE_EXECUTABLE_IMAGE|
			IMAGE_FILE_32BIT_MACHINE|
			IMAGE_FILE_DLL|
			IMAGE_FILE_LINE_NUMS_STRIPPED|
			IMAGE_FILE_LOCAL_SYMS_STRIPPED;
	}


	NTHeaders->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);


	NTHeaders->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	NTHeaders->OptionalHeader.SizeOfUninitializedData = 0;
	NTHeaders->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	//Linker Version
	NTHeaders->OptionalHeader.MajorLinkerVersion = 0;
	NTHeaders->OptionalHeader.MinorLinkerVersion = 0;

	//PE开始代码段的开始
	NTHeaders->OptionalHeader.AddressOfEntryPoint = 0x1000;
	//设置代码的开始地址RVA
	NTHeaders->OptionalHeader.BaseOfCode = 0x1000;

	NTHeaders->OptionalHeader.SizeOfUninitializedData = 0;

	//设置文件区段对齐信息
	NTHeaders->OptionalHeader.SectionAlignment = 0x1000;
	NTHeaders->OptionalHeader.FileAlignment = 0x200;

	//设置OS版本
	NTHeaders->OptionalHeader.MajorOperatingSystemVersion = 4;
	NTHeaders->OptionalHeader.MinorOperatingSystemVersion = 0;

	NTHeaders->OptionalHeader.MajorImageVersion = 0;
	NTHeaders->OptionalHeader.MinorImageVersion = 0;

	NTHeaders->OptionalHeader.MajorSubsystemVersion = 4;
	NTHeaders->OptionalHeader.MinorSubsystemVersion = 0;
	//不需要
	NTHeaders->OptionalHeader.Win32VersionValue = 0;

	NTHeaders->OptionalHeader.SizeOfHeaders = PE_IMAGE_HEADER_SIZE;

	//不需要校验和
	NTHeaders->OptionalHeader.CheckSum = 0;

	if(ProcGUI == TRUE)
	{
		NTHeaders->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	}
	else
	{
		NTHeaders->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
	}
	NTHeaders->OptionalHeader.DllCharacteristics = 0;

	NTHeaders->OptionalHeader.SizeOfStackReserve = 0x100000;
	NTHeaders->OptionalHeader.SizeOfStackCommit = 0x1000;
	NTHeaders->OptionalHeader.SizeOfHeapReserve = 0x100000;
	NTHeaders->OptionalHeader.SizeOfHeapCommit = 0x1000;

	NTHeaders->OptionalHeader.LoaderFlags = 0;
	NTHeaders->OptionalHeader.ImageBase = ImageBase;
}

vector <ImportInfoBuild> BuildImportList;

DWORD PEBuilder::GetImportRva(string DllName,string APIName)
{
	DWORD rva = 0;
	DWORD RvaOfPEImport = GetNameRva("PEImportJmp");
	DWORD Index = -1;
	Index = TreeImport.GetImportIndex(DllName,APIName);

	if(Index != -1)
	{
		rva = RvaOfPEImport + sizeof(JmpCode) * Index;
	}

	return rva;
}
DWORD PEBuilder::WriteString(BYTE*& ImportData,DWORD& ImportDataLen,string addString)
{
	DWORD offset = ImportDataLen;

	DWORD str_length = addString.length() + 1;

	ImportDataLen += str_length;

	ImportData = (BYTE*)realloc(ImportData,ImportDataLen);

	strcpy((char*)&ImportData[offset],addString.c_str());

	return offset;
}
DWORD PEBuilder::WriteImportByName(BYTE*& ImportData,DWORD& ImportDataLen,string addString)
{
	DWORD offset = ImportDataLen;


	DWORD ByNameLen = sizeof(WORD) + addString.length() + 1;

	PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)malloc(ByNameLen);

	ImportByName->Hint = 0;
	strcpy((char*)&ImportByName->Name[0],addString.c_str());
	

	ImportDataLen += ByNameLen;

	ImportData = (BYTE*)realloc(ImportData,ImportDataLen);

	memcpy(&ImportData[offset],ImportByName,ByNameLen);

	free(ImportByName);

	return offset;
}

void PEBuilder::BuildImportThunk(string ModuleName,vector<ImportThunk> vectors,
					  DWORD& ref_index,BYTE*& ImportData,DWORD& ImportDataLen)
{
	ImportInfoBuild ImportBuild;
	BuildAPIInfo APIInfo;
	ImportBuild.ModuleName = ModuleName;
	ImportBuild.offset = WriteString(ImportData,ImportDataLen,ModuleName);
	printf("正在构建导出表 模块:%s\n函数:\n",&ImportData[ImportBuild.offset]);

	for(DWORD i=0;i<vectors.size();i++)
	{
		APIInfo.APIName = vectors[i].APIName;
		APIInfo.ThunkIndex = ref_index;
		APIInfo.offset = WriteImportByName(ImportData,ImportDataLen,vectors[i].APIName);

		printf("%s\n",&ImportData[APIInfo.offset] + sizeof(WORD));
		ref_index++;
		ImportBuild.APIList.push_back(APIInfo);
		
	}

	BuildImportList.push_back(ImportBuild);
}
void PEBuilder::RelevanceImport(DWORD rva_Import_List,BYTE*& ImportData,DWORD& ImportDataLen,DWORD ImportDataRva)
{
	char impstring[64];
	string imp_ft_string;
	string imp_oft_string;

	for(DWORD i=0;i<BuildImportList.size();i++)
	{
		ImportInfoBuild& ImportBuild = BuildImportList[i];
		ImportBuild.ImportDes.Name = (ImportDataRva + ImportBuild.offset) - NTHeaders->OptionalHeader.ImageBase; 
		ImportBuild.ImportDes.ForwarderChain = -1;

		ImportBuild.FirstThunk = (PIMAGE_THUNK_DATA32)(GetNameDataMem("IAT") + ImportBuild.APIList[0].ThunkIndex * sizeof(DWORD));
		ImportBuild.OriginalFirstThunk = (PIMAGE_THUNK_DATA32)realloc(ImportBuild.OriginalFirstThunk,(ImportBuild.APIList.size() + 1) * sizeof(IMAGE_THUNK_DATA32));

		for(DWORD j=0;j<ImportBuild.APIList.size();j++)
		{
			BuildAPIInfo& APIInfo = ImportBuild.APIList[j];
			ImportBuild.FirstThunk[j].u1.Function = (rva_Import_List + sizeof(DWORD) * APIInfo.ThunkIndex) - NTHeaders->OptionalHeader.ImageBase;		
			ImportBuild.OriginalFirstThunk[j].u1.ForwarderString = (ImportDataRva + APIInfo.offset) - NTHeaders->OptionalHeader.ImageBase;
			ImportBuild.FirstThunk[j+1].u1.Function = 0;
			ImportBuild.OriginalFirstThunk[j+1].u1.ForwarderString = 0;
		}

		sprintf(impstring,"imp_ft_%s",ImportBuild.ModuleName.c_str());
		imp_ft_string = impstring;
		sprintf(impstring,"imp_oft_%s",ImportBuild.ModuleName.c_str());
		imp_oft_string = impstring;
		

		BuildSection((char*)imp_oft_string.c_str(),(BYTE*)ImportBuild.OriginalFirstThunk,(ImportBuild.APIList.size() + 1) * sizeof(IMAGE_THUNK_DATA32),SEC_DATA);
		DWORD ftrva = (rva_Import_List + ImportBuild.APIList[0].ThunkIndex * sizeof(DWORD)) - NTHeaders->OptionalHeader.ImageBase;
		DWORD oftrva = GetNameRva(imp_oft_string.c_str()) - NTHeaders->OptionalHeader.ImageBase;
		ImportBuild.ImportDes.FirstThunk = ftrva;
		ImportBuild.ImportDes.OriginalFirstThunk = oftrva;
		ImportBuild.ImportDes.TimeDateStamp = 0;
	}	
}

void PEBuilder::BuildAppendImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR &pImportDescrptor,DWORD& ModuleCount)
{
	ModuleCount = BuildImportList.size();

	pImportDescrptor = (PIMAGE_IMPORT_DESCRIPTOR)realloc(pImportDescrptor,sizeof(IMAGE_IMPORT_DESCRIPTOR) * (ModuleCount + 1));
	
	memset(pImportDescrptor,0,sizeof(IMAGE_IMPORT_DESCRIPTOR) * (ModuleCount + 1));
	for(DWORD i=0;i<BuildImportList.size();i++)
	{
		pImportDescrptor[i] = BuildImportList[i].ImportDes;
	}
	BuildSection("ImportDescriptor",(BYTE*)pImportDescrptor,sizeof(IMAGE_IMPORT_DESCRIPTOR) * (ModuleCount + 1),SEC_DATA);
}

void PEBuilder::BuildPEImport()
{
	vector <ImportCreateThunk> ImportList = TreeImport.BuildImportCreateList();
	JmpCode* JmpCodeList = new JmpCode[ImportList.size()];
	BYTE* ImportData = (BYTE*)malloc(0);
	DWORD ImportDataLen = 0;
	DWORD ImportDataRva = 0;
	DWORD rva_Import_List;
	DWORD ref_index = 0;

	PIMAGE_IMPORT_DESCRIPTOR pImportDescrptor = (PIMAGE_IMPORT_DESCRIPTOR)malloc(0);
	DWORD ModuleCount = 0;
	

	rva_Import_List = GetNameRva("IAT");

	BuildBlock* Block = BuildSection("PEImportJmp",(BYTE*)JmpCodeList,sizeof(JmpCode) * ImportList.size(),SEC_CODE);

	delete [] JmpCodeList;

	JmpCodeList = (JmpCode*)GetNameDataMem("PEImportJmp");

	Block->SetRelocCount(ImportList.size());

	for(DWORD i=0;i<ImportList.size();i++)
	{
		JmpCodeList[i].nix = 0xFF;
		JmpCodeList[i].code = 0x25;
		JmpCodeList[i].Address = rva_Import_List + i * sizeof(DWORD);
		//重定位信息
		Block->PointOfReloc[i] = sizeof(JmpCode) * i + sizeof(WORD);
	}

	

	//TreeImport.ImportTreeList.size()
	for(map <string,vector <ImportThunk>>::iterator iter = TreeImport.ImportTreeList.begin(); iter != TreeImport.ImportTreeList.end();iter++)
	{
		BuildImportThunk(iter->first,iter->second,ref_index,ImportData,ImportDataLen);
	}

	BuildSection("PEImportData",(BYTE*)ImportData,ImportDataLen,SEC_DATA);

	free(ImportData);

	ImportData = (BYTE*)GetNameDataMem("PEImportData");

	ImportDataRva = GetNameRva("PEImportData");


	RelevanceImport(rva_Import_List,ImportData,ImportDataLen,ImportDataRva);
	
	BuildAppendImportDescriptor(pImportDescrptor,ModuleCount);
}
BYTE* PEBuilder::BuildSectionData(ImageSection& Section,DWORD& DataLength)
{
	DWORD CopyOffset = 0;
	BYTE* Buffer = (BYTE *)malloc(Section.EndOfRva);
	memset(Buffer,0,Section.EndOfRva);

	DataLength = Section.EndOfRva;

	for(DWORD i=0;i<Section.BuildDataList.size();i++)
	{
		memcpy(&Buffer[CopyOffset],Section.BuildDataList[i]->Buffer,Section.BuildDataList[i]->BufferLength);
		CopyOffset += Section.BuildDataList[i]->BufferLength;
		printf("正在编译节:%s\n",Section.BuildDataList[i]->Name.c_str());
	}

	return Buffer;
}
VOID PEBuilder::GetSectionRelocation(ImageSection& Section)
{
	for(DWORD i=0;i<Section.BuildDataList.size();i++)
	{
		for (DWORD j=0;j<Section.BuildDataList[i]->NumberOfReloc;j++)
		{
			RelocAddressList.push_back(Section.BuildDataList[i]->PointOfReloc[j] + Section.BuildDataList[i]->DataRVA + Section.StartAddress);
		}
	}
}

typedef vector <DWORD> RelSubList_t;

VOID PEBuilder::CreateRelocSection()
{
	vector <RelSubList_t> RelListArray;
	GetSectionRelocation(SecText);
	GetSectionRelocation(SecData);
	GetSectionRelocation(SecRsrc);

	sort(RelocAddressList.begin(), RelocAddressList.end());

	printf("正在创建重定位区段信息.....\n");
	for(DWORD i=0;i<RelocAddressList.size();)
	{
		RelSubList_t RelocSubList;
		DWORD Page = RelocAddressList[i] & 0xFFFFF000;
		do 
		{
			if(i >= RelocAddressList.size() || (RelocAddressList[i] & 0xFFFFF000) != Page)
				break;
			RelocSubList.push_back(RelocAddressList[i]);
			i++;
		} while (true);

		RelListArray.push_back(RelocSubList);
	}
	BYTE* RelocData = (BYTE*)malloc(0);
	DWORD RelocDataLength = 0;

	IMAGE_BASE_RELOCATION BaseRelocation;

	for(DWORD i=0;i<RelListArray.size();i++)
	{
		RelSubList_t relSubList = RelListArray[i];

		
		BaseRelocation.VirtualAddress = relSubList[0] - NTHeaders->OptionalHeader.ImageBase & 0xFFFFF000;
		BaseRelocation.SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + relSubList.size() * sizeof(WORD);
		BYTE* RelData = new BYTE[BaseRelocation.SizeOfBlock];
		memcpy(RelData,&BaseRelocation,sizeof(IMAGE_BASE_RELOCATION));
		WORD* RelItem =(WORD*)&RelData[sizeof(IMAGE_BASE_RELOCATION)];
		for(DWORD j=0;j<relSubList.size();j++)
		{
			RelItem[j] = (relSubList[j] & 0x0FFF) | (IMAGE_REL_BASED_HIGHLOW << 12);
		}

		DWORD AllocateSize = RelocDataLength + BaseRelocation.SizeOfBlock;

		RelocData = (BYTE*)realloc(RelocData,AllocateSize);

		memcpy(&RelocData[RelocDataLength],RelData,BaseRelocation.SizeOfBlock);

		RelocDataLength = AllocateSize;

		delete [] RelData;
	}


	BuildBlock* Block = BuildSection("PERelocation",RelocData,RelocDataLength,SEC_RELOC);
}
void PEBuilder::BuildPEFormat()
{
	CreateRelocSection(); 
	BuildExportTable();

	
	/*
	.text
	.rdata
	.data
	.rsrc
	.reloc
	*/

	printf("正在构建PE区段.....\n");
	NTHeaders->FileHeader.NumberOfSections = 4;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(NTHeaders);
	
	strcpy((char*)&pSection[0].Name,".text");
	
	pSection[0].Misc.VirtualSize = AlignToMem(AlignToFile(SecText.EndOfRva));
	pSection[0].PointerToRawData = NTHeaders->OptionalHeader.SizeOfHeaders;
	pSection[0].SizeOfRawData = AlignToFile(SecText.EndOfRva);
	pSection[0].VirtualAddress = SecTextBegin - NTHeaders->OptionalHeader.ImageBase;
	pSection[0].NumberOfRelocations = 0;
	pSection[0].NumberOfLinenumbers = 0;
	pSection[0].PointerToRelocations = 0;
	pSection[0].PointerToLinenumbers = 0;
	pSection[0].Characteristics = IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE;

	strcpy((char*)&pSection[1].Name,".data");
	pSection[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;
	pSection[1].PointerToRawData = pSection[0].PointerToRawData + pSection[0].SizeOfRawData;
	pSection[1].Misc.VirtualSize = AlignToMem(AlignToFile(SecData.EndOfRva));
	pSection[1].SizeOfRawData = AlignToFile(SecData.EndOfRva);
	pSection[1].VirtualAddress = SecDataBegin - NTHeaders->OptionalHeader.ImageBase;
	pSection[1].NumberOfRelocations = 0;
	pSection[1].NumberOfLinenumbers = 0;
	pSection[1].PointerToRelocations = 0;
	pSection[1].PointerToLinenumbers = 0;

	strcpy((char*)&pSection[2].Name,".rsrc");
	pSection[2].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ;
	pSection[2].PointerToRawData = pSection[1].PointerToRawData + pSection[1].SizeOfRawData;
	pSection[2].Misc.VirtualSize = AlignToMem(AlignToFile(SecRsrc.EndOfRva));
	pSection[2].SizeOfRawData = AlignToFile(SecRsrc.EndOfRva);
	pSection[2].VirtualAddress = SecRsrcBegin - NTHeaders->OptionalHeader.ImageBase;
	pSection[2].NumberOfRelocations = 0;
	pSection[2].NumberOfLinenumbers = 0;
	pSection[2].PointerToRelocations = 0;
	pSection[2].PointerToLinenumbers = 0;


	strcpy((char*)&pSection[3].Name,".reloc");
	pSection[3].Characteristics = IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_DISCARDABLE|IMAGE_SCN_CNT_INITIALIZED_DATA;
	pSection[3].PointerToRawData = pSection[2].PointerToRawData + pSection[2].SizeOfRawData;
	pSection[3].Misc.VirtualSize = AlignToMem(AlignToFile(SecReloc.EndOfRva));
	pSection[3].SizeOfRawData = AlignToFile(SecReloc.EndOfRva);
	pSection[3].VirtualAddress = SecRelocBegin - NTHeaders->OptionalHeader.ImageBase;
	pSection[3].NumberOfRelocations = 0;
	pSection[3].NumberOfLinenumbers = 0;
	pSection[3].PointerToRelocations = 0;
	pSection[3].PointerToLinenumbers = 0;

	
	NTHeaders->OptionalHeader.SizeOfCode = pSection[0].SizeOfRawData;
	NTHeaders->OptionalHeader.BaseOfData = pSection[1].VirtualAddress;
	NTHeaders->OptionalHeader.SizeOfInitializedData = AlignToFile(pSection[1].SizeOfRawData) + AlignToFile(pSection[2].SizeOfRawData) + AlignToFile(pSection[3].SizeOfRawData);
	NTHeaders->OptionalHeader.SizeOfImage = AlignToMem(NTHeaders->OptionalHeader.SizeOfHeaders) + pSection[0].Misc.VirtualSize + pSection[1].Misc.VirtualSize + pSection[2].Misc.VirtualSize + pSection[3].Misc.VirtualSize;
	NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = GetNameDataSize("ImportDescriptor");
	NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = GetNameRva("ImportDescriptor") - NTHeaders->OptionalHeader.ImageBase;

	NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = GetNameDataSize("PERelocation");
	NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = GetNameRva("PERelocation") - NTHeaders->OptionalHeader.ImageBase;

	if(GetNameBlock("ExportDirectory") != NULL)
	{
		NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = GetNameDataSize("ExportDirectory") + GetNameDataSize("ExportStrName") + GetNameDataSize("ExportNameOrdTable")
			+ GetNameDataSize("ExportAddressOfName") + GetNameDataSize("ExportFuncTable");
		NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = GetNameRva("ExportDirectory") - NTHeaders->OptionalHeader.ImageBase;
	}

	if(GetNameBlock("ResourcesData") != NULL)
	{
		NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = GetNameDataSize("ResourcesData");
		NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = GetNameRva("ResourcesData") - NTHeaders->OptionalHeader.ImageBase;
	}
	DWORD DataLength;

	BYTE* BuildBuf;

	printf("开始编译区段.....\n");

	DWORD WriteOffset = 0;
	BYTE* PEData = (BYTE*)malloc(NTHeaders->OptionalHeader.SizeOfHeaders);

	memset(&PEData[WriteOffset],0,NTHeaders->OptionalHeader.SizeOfHeaders);
	memcpy(&PEData[WriteOffset],ImageHeaderData,NTHeaders->OptionalHeader.SizeOfHeaders);
	WriteOffset += NTHeaders->OptionalHeader.SizeOfHeaders;

	//编译代码段
	PEData = (BYTE*)realloc(PEData,WriteOffset + pSection[0].SizeOfRawData);
	memset(&PEData[WriteOffset],0,pSection[0].SizeOfRawData);
	BuildBuf = BuildSectionData(SecText,DataLength);
	memcpy(&PEData[WriteOffset],BuildBuf,DataLength);
	free(BuildBuf);

	WriteOffset += pSection[0].SizeOfRawData;

	//编译DATA段
	PEData = (BYTE*)realloc(PEData,WriteOffset + pSection[1].SizeOfRawData);
	memset(&PEData[WriteOffset],0,pSection[1].SizeOfRawData);
	BuildBuf = BuildSectionData(SecData,DataLength);
	memcpy(&PEData[WriteOffset],BuildBuf,DataLength);
	free(BuildBuf);
	WriteOffset += pSection[1].SizeOfRawData;


	//编译rsrc段
	PEData = (BYTE*)realloc(PEData,WriteOffset + pSection[2].SizeOfRawData);
	memset(&PEData[WriteOffset],0,pSection[2].SizeOfRawData);
	BuildBuf = BuildSectionData(SecRsrc,DataLength);
	memcpy(&PEData[WriteOffset],BuildBuf,DataLength);
	free(BuildBuf);
	WriteOffset += pSection[2].SizeOfRawData;

	//编译reloc段
	PEData = (BYTE*)realloc(PEData,WriteOffset + pSection[3].SizeOfRawData);
	memset(&PEData[WriteOffset],0,pSection[3].SizeOfRawData);
	BuildBuf = BuildSectionData(SecReloc,DataLength);
	memcpy(&PEData[WriteOffset],BuildBuf,DataLength);
	free(BuildBuf);
	WriteOffset += pSection[3].SizeOfRawData;

	printf("文件重构完成...准备写出文件...\n");
	FILE* f = fopen(szOutputName,"wb");

	if(f)
	{
		fwrite(PEData,WriteOffset,1,f);
		fclose(f);

		printf("文件重构完成\n");
	}
	else
	{
		printf("无法打开输出文件\n");
	}

	


}
DWORD PEBuilder::AlignToFile(DWORD ad)
{
	DWORD a1 = ad;
	if(!a1)
		return 0;

	if((ad % NTHeaders->OptionalHeader.FileAlignment) != 0)
	{
		a1 -= (ad % NTHeaders->OptionalHeader.FileAlignment);
		a1 += NTHeaders->OptionalHeader.FileAlignment;
	}
	return a1;
}
DWORD PEBuilder::AlignToMem(DWORD ad)
{
	DWORD a1 = ad;
	if(!a1) a1 = NTHeaders->OptionalHeader.SectionAlignment;

	if((ad % NTHeaders->OptionalHeader.SectionAlignment) != 0)
	{
		a1 -= (ad % NTHeaders->OptionalHeader.SectionAlignment);
		a1 += NTHeaders->OptionalHeader.SectionAlignment;
	}
	return a1;
}

VOID PEBuilder::AddExportFunction(string FuncName,string BlockName,DWORD Offset)
{
	CompileExport CCExport;

	CCExport.ImageRva = Offset;
	CCExport.szBlockName = BlockName;
	CCExport.szFuncName = FuncName;

	CExportList.push_back(CCExport);
}

VOID PEBuilder::BuildExportTable()
{
	IMAGE_EXPORT_DIRECTORY ExpDir = {0};
	printf("正在创建导出表信息...\n");
	if(CExportList.size() > 0)
	{
		char* pStrTable = (char*)malloc(0);
		DWORD StrLength = 0;
		DWORD* pFunctionTable = new DWORD[CExportList.size()];
		WORD* pNameOrdinalsTable = new WORD[CExportList.size()];
		DWORD* pAddressOfNameTable = new DWORD[CExportList.size()];

		BuildBlock* pExpDirBlock = BuildSection("ExportDirectory",(BYTE*)&ExpDir,sizeof(ExpDir),SEC_DATA);
		PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)GetNameDataMem("ExportDirectory");
		pExpDir->Base = 1;
		pExpDir->NumberOfFunctions = CExportList.size();
		pExpDir->NumberOfNames = CExportList.size();

		
		for(DWORD i=0;i<CExportList.size();i++)
		{
			DWORD AllocLen = StrLength + (strlen(CExportList[i].szFuncName.c_str()) + 1);

			pStrTable = (char*)realloc(pStrTable,AllocLen);
			strcpy(&pStrTable[StrLength],CExportList[i].szFuncName.c_str());

			pAddressOfNameTable[i] = StrLength;
			pNameOrdinalsTable[i] = (WORD)i;
			pFunctionTable[i] = CExportList[i].ImageRva - NTHeaders->OptionalHeader.ImageBase;

			StrLength = AllocLen;
		}
		
		BuildBlock * ExportStrName = BuildSection("ExportStrName",(BYTE*)pStrTable,StrLength,SEC_DATA);
		BuildBlock * ExportFuncTable = BuildSection("ExportFuncTable",(BYTE*)pFunctionTable,sizeof(DWORD) * CExportList.size(),SEC_DATA);
		BuildBlock * ExportNameOrdTable = BuildSection("ExportNameOrdTable",(BYTE*)pNameOrdinalsTable,sizeof(WORD) * CExportList.size(),SEC_DATA);
		BuildBlock * ExportAddressOfName = BuildSection("ExportAddressOfName",(BYTE*)pAddressOfNameTable,sizeof(DWORD) * CExportList.size(),SEC_DATA);

		delete [] pFunctionTable;
		delete [] pNameOrdinalsTable;
		delete [] pAddressOfNameTable;
		free(pStrTable);

		pAddressOfNameTable = (DWORD*)GetNameDataMem("ExportAddressOfName");
		DWORD NameRva = GetNameRva("ExportStrName") - NTHeaders->OptionalHeader.ImageBase;
		for(DWORD i=0;i<CExportList.size();i++)
		{
			pAddressOfNameTable[i] += NameRva;
		}


		pExpDir->AddressOfNames = GetNameRva("ExportAddressOfName") - NTHeaders->OptionalHeader.ImageBase;
		pExpDir->AddressOfNameOrdinals = GetNameRva("ExportNameOrdTable") - NTHeaders->OptionalHeader.ImageBase;
		pExpDir->AddressOfFunctions = GetNameRva("ExportFuncTable") - NTHeaders->OptionalHeader.ImageBase;
		pExpDir->Name = GetNameRva("ExportStrName") - NTHeaders->OptionalHeader.ImageBase;
	}
}