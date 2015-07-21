#ifndef _PE_BUILDER_H_
#define _PE_BUILDER_H_

#define SEC_CODE 0
#define SEC_DATA 1
#define SEC_RDATA 2
#define SEC_RSRC 3
#define SEC_RELOC 4


class BuildBlock
{
public:
	string Name;
	DWORD DataRVA;
	PBYTE Buffer;
	PDWORD PointOfReloc;
	DWORD BufferLength;
	DWORD NumberOfReloc;
	
	BuildBlock();
	VOID ReSize(DWORD BufSize);
	VOID SetRelocCount(DWORD Count);
	~BuildBlock();
};


class ImageSection
{
public:
	string SectionName;
	DWORD StartAddress;
	DWORD EndOfRva;
	vector <BuildBlock*> BuildDataList;

	BuildBlock* BuildSection(CHAR* Name,BYTE* Data,DWORD Length);
	BuildBlock * FindName(string Name);
	ImageSection();
};

class ImportThunk
{
public:
	string DllName;
	string APIName;
	DWORD Index;
};

class ImportCreateThunk
{
public:
	string DllName;
	string APIName;
	DWORD Index;
};

class BuildAPIInfo
{
public:
	string APIName;
	DWORD offset;
	DWORD ThunkIndex;
};
class ImportInfoBuild
{
public:
	ImportInfoBuild()
	{
		memset(&ImportDes,0,sizeof(ImportDes));
		OriginalFirstThunk = (PIMAGE_THUNK_DATA32)malloc(0);
		FirstThunk = (PIMAGE_THUNK_DATA32)malloc(0);
	}
	IMAGE_IMPORT_DESCRIPTOR ImportDes;
	PIMAGE_THUNK_DATA32 OriginalFirstThunk;
	PIMAGE_THUNK_DATA32 FirstThunk;
	DWORD offset;
	string ModuleName;
	vector <BuildAPIInfo> APIList;
};

class ImportTree
{
public:
	map <string,vector <ImportThunk>> ImportTreeList;
	ImportTree()
	{
		ImportTreeList.clear();
	}
	void AddImport(string DllName,string APIName);
	DWORD GetImportIndex(string DllName,string APIName);
	vector <ImportCreateThunk> BuildImportCreateList();
};

class CompileExport
{
public:
	string szFuncName;
	string szBlockName;
	DWORD ImageRva;
};
class PEBuilder
{
public:
	DWORD ImageBase;
	PBYTE ImageHeaderData;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS NTHeaders;

	ImageSection SecText;
	ImageSection SecData;
	ImageSection SecRData;
	ImageSection SecRsrc;
	ImageSection SecReloc;


	DWORD SecTextBegin;
	DWORD SecDataBegin;
	DWORD SecRDataBegin;
	DWORD SecRsrcBegin;
	DWORD SecRelocBegin;

	ImportTree TreeImport;

	vector <DWORD> RelocAddressList;

	vector <CompileExport> CExportList;

	DWORD GetNameRva(string Name);
	BYTE* GetNameDataMem(string Name);
	DWORD GetNameDataSize(string Name);
	string GetModuleString(string ModuleName);
	BuildBlock* GetNameBlock(string Name);
	BuildBlock* BuildSection(CHAR* Name,BYTE* Data,DWORD Length,DWORD Block);

	void BuildPEImport();
	void BuildAppendImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR &pImportDescrptor,DWORD& ModuleCount);
	void RelevanceImport(DWORD rva_Import_List,BYTE*& ImportData,DWORD& ImportDataLen,DWORD ImportDataRva);
	void BuildImportThunk(string ModuleName,vector<ImportThunk> vectors,
		DWORD& ref_index,BYTE*& ImportData,DWORD& ImportDataLen);
	DWORD WriteImportByName(BYTE*& ImportData,DWORD& ImportDataLen,string addString);
	DWORD WriteString(BYTE*& ImportData,DWORD& ImportDataLen,string addString);

	DWORD GetImportRva(string DllName,string APIName);

	VOID AddExportFunction(string FuncName,string BlockName,DWORD Offset);

	void BuildPEFormat();

	void CalcSectionRva();
	BYTE* BuildSectionData(ImageSection& Section,DWORD& DataLength);
	PEBuilder(DWORD BaseAddr,BOOL IsDllFile,BOOL ProcGUI);
	~PEBuilder();

	DWORD AlignToMem(DWORD ad);
	DWORD AlignToFile(DWORD ad);

	VOID BuildRelocInfo();

	VOID BuildExportTable();

	VOID CreateRelocSection();

	VOID GetSectionRelocation(ImageSection& Section);

};


#endif