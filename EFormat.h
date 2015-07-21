
#ifndef _EFORMAT_H_
#define _EFORMAT_H_

#pragma pack(4)

#define IMAGE_E_SIGNATURE 0x00004A57
//易语言区段描述信息
typedef struct _E_SECTION_INFO_HEADER
{
	DWORD OffsetOfData;				//当前区段的地址+OffsetOfData = 区段的数据地址
	DWORD NextSectionRva;			//下一个区段的RVA,如果当前是最后一个区段则这个值是-1
	BYTE  UnknownByte;				//未知数据,占用4字节(4字节对齐)
}E_SECTION_INFO_HEADER,*PE_SECTION_INFO_HEADER;

//易语言重定位信息
typedef struct _E_SECTION_RELOC_HEADER
{
	DWORD NumberOfReloc;			//重定位的个数
	DWORD RelocArray[1];			//重定位数据的数组,从1开始,跳过0
}E_SECTION_RELOC_HEADER,*PE_SECTION_RELOC_HEADER;

/*
	E_SECTION_RELOC_ADDR RelocAddr;
	易语言重定位详细信息
	DWORD RelocBlock = RelocArray[i];

	//获取重定位标识信息
	DWORD IndexOfRelocAdr = RelocBlock & 0x7;

	//获得重定位偏移
	RelocBlock >>= 3;

	//需要重定位的地址
	DWORD* RelocPtr = (DWORD*)SectionDataOffset + RelocBlock;

	//进行重定位
	*RelocPtr += ((DWORD*)RelocAddr)[IndexOfRelocAdr];
*/
#define E_RELOC_HELP 0 
#define E_RELOC_CONST 1
#define E_RELOC_VAR	2
#define E_RELOC_CODE 3

//易语言重定位标识信息
typedef struct _E_SECTION_RELOC_ADDR
{
	DWORD PointOfHelp;
	DWORD PointOfConst;
	DWORD PointOfVar;
	DWORD PointOfCode;
}E_SECTION_RELOC_ADDR,*PE_SECTION_RELOC_ADDR;


//易语言区段信息
typedef struct _E_SECTION_HEADER
{
	E_SECTION_INFO_HEADER Info;	//区段描述信息,保存下一个区段和区段数据的偏移
	CHAR Name[24];						//区段的名字
	DWORD SizeOfRva;					//当前区段RVA的大小
	DWORD SizeOfRaw;					//当前区段的RAW大小
	DWORD DataRva;						//当前数据的RVA(从E_HEADER的位置起始的偏移)
	E_SECTION_RELOC_HEADER RelocInfo;	//重定位表的信息
}E_SECTION_HEADER,*PE_SECTION_HEADER;

typedef struct _E_HEADER
{
	CHAR Signature[0x24];		//易语言头部标记
	DWORD RvaOfDataStart;		//易语言数据的开始地址(跳过易语言导入表信息和支持库信息)
	DWORD UnknownDWORD1;		//数据未知,永远等于1
	DWORD UnknownDWORD2;		//数据未知,永远等于3
	BOOL IsDllModule;			//TRUE = DLL,FALSE = EXE
	DWORD UnknownDWORD3;		//数据未知,不定量
	DWORD NumberOfDllImport;	//易语言导入表数量(DLL API数量)
	DWORD RvaOfEntry;			//易语言代码的OEP
	DWORD RvaOfConst;			//易语言数据附加段 空则是-1
	DWORD RvaOfForm;			//易语言窗口数据段
	DWORD RvaOfHelp;			//易语言支持库接口
	DWORD RvaOfCode;			//易语言的代码段
	DWORD RvaOfVar;				//易语言的变量段
	DWORD RvaOfFirstSection;	//易语言区段开始
}E_HEADER,*PE_HEADER;

/*
跟在E_HEADER后面的就是Import的偏移
导入表具体结构
总共有NumberOfDllImport * sizeof(DWORD)个Dll的Rva和NameRva

DWORD ImportIndex(DllName) 0 
DWORD ImportIndex(DllName) 1
DWORD ImportIndex(DllAPI) 0
DWORD ImportIndex(DllAPI) 1
*/

//导入表之后就是支持库,以0x0D为分隔符
/*
	支持库LibName
	支持库GUID
	支持库版本(Major)
	支持库版本(Minor)
	支持库中文名
*/
/*
004031C2  73 70 65 63 0D 41 35 31 32 35 34 38 45 37 36 39  spec.A512548E769
004031D2  35 34 42 36 45 39 32 43 32 31 30 35 35 35 31 37  54B6E92C21055517
004031E2  36 31 35 42 30 0D 33 0D 30 0D CC D8 CA E2 B9 A6  615B0.3.0.特殊功
004031F2  C4 DC D6 A7 B3 D6 BF E2 00 00 DC 00 00 00 40 09  能支持库..?..@.
*/

//易语言调用表
//这个是指向help段的数据数组,代表虚函数
typedef struct _E_LIB_CALL
{
	DWORD MReportError;
	DWORD MCallDllCmd;
	DWORD MCallLibCmd;
	DWORD MCallKrnlLibCmd;
	DWORD MReadProperty;
	DWORD MWriteProperty;
	DWORD MMalloc;
	DWORD MRealloc;
	DWORD MFree;
	DWORD MExitProcess;
	DWORD MMessageLoop;
	DWORD MLoadBeginWin;
	DWORD MOtherHelp;
}E_LIB_CALL,*PE_LIB_CALL;


#pragma pack()

#endif