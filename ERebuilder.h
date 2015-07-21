
#ifndef _E_REBUILDER_H_
#define _E_REBUILDER_H_
#pragma pack(4)
typedef struct MemorySection
{
	string Name;
	DWORD SizeOfRva;
	DWORD SizeOfRaw;
	BYTE* DataPointer;
	BYTE UnknownByte;
	PE_SECTION_RELOC_HEADER Relocation;
}MemorySection;
#pragma pack()

class ELibItem
{
public:
	string libModule;
	string libGUID;
	string libmajorVersion;
	string libminorVersion;
	string libChnName;
};

class ExportItem
{
public:
	string szName;
	DWORD ExportRvaOrg;
	DWORD ExportRawOrg;
	DWORD OffsetOfCode;
	DWORD OffsetOfEInfo;
};

class ResNode
{
public:
	//目录还是叶子节点
	BOOL IsDirectory;
	vector <ResNode*> NextNode;

	IMAGE_RESOURCE_DIRECTORY ResDir;


	IMAGE_RESOURCE_DATA_ENTRY ResDataEntry;
	
	BYTE* Data;
	DWORD DataLength;
};

class ERebuilder
{
public:
	BYTE* PEImage;
	DWORD PELength;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS NTHeaders;

	ResNode* TopNode;

	BYTE* PointOfECode;
	DWORD ECodeLength;

	PE_HEADER EHeader;
	PEBuilder * Builder;

	BOOL IsCUI;
	BOOL IsDLL;
	BOOL Status;

	vector <ImportThunk> EImportList;
	vector <MemorySection> ESectionList;
	vector <ELibItem> ELibList;


	vector <ExportItem> ExportList;

	VOID CopyResBuf();
	VOID FixupExportAddress(PE_SECTION_HEADER SectionThunk);
	ERebuilder(BYTE* ImageOfMemory,DWORD LengthOfImage);

	VOID FixECodeCallAPI();

	MemorySection* GetSectionInfo(string sectionName);

	VOID AddChildNode(DWORD tableAddress,PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry, int depth,int Type=-1);

	VOID GetECodeInformation();
	VOID BuildEStartup();
	VOID GetEImport();
	VOID GetESection();
	VOID ReservedImportSize();
	VOID CopySectionData();
	VOID BuildSectionOffset(E_SECTION_RELOC_ADDR& RelocOffset);
	VOID LoadRelocBySection(DWORD *RelocAdr,MemorySection* Section);
	VOID BuildEImportInfo(BYTE*& ImportPtr,DWORD& ImportLen);
	VOID BuildELibPtr(BYTE*& ELibPtr,DWORD& ELibLen);
	VOID EBuildSection(BYTE*& ESectionPtr,DWORD& SectionLength);
	VOID CreateHeader(E_HEADER*& pEHeader);
	DWORD GetSectionIndex(string Name);
	VOID FixEStartupCallAPI();

	VOID BuildEHeader();

	VOID LoadRelocation();
	VOID GetLibInfo();

	VOID AddEExportInfo();

	BOOL IsSuccess();
};


#endif

