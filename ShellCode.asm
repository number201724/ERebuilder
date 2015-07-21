.686
.model flat,stdcall
option casemap:none

include masm32\include\windows.inc
include masm32\include\kernel32.inc
include masm32\include\user32.inc
include masm32\include\advapi32.inc

.code
;除法优化
MyDiv proc a,b
	mov eax,a
	cdq
	idiv b
	ret
MyDiv endp
;乘法优化
MyMul proc a,b
	mov eax,a
	imul eax,b
	ret
MyMul endp
;加法优化
MyAdd proc a,b
	mov eax,a
	add eax,b
	ret
MyAdd endp
;减法优化
MySub proc a,b
	mov eax,a
	sub eax,b
	ret
MySub endp

EXEDataInfo struct
	pEKrnlnName dd ?
	pEInstallReg dd ?
	pEErrorMsg dd ?
	pEErrorTitle dd ?
	pEStrPath dd ?
	pEStrGetNewSock dd ?
EXEDataInfo ends


EXE_Info_Label_Start:
EKrnlnName db 'krnln.fnr',0
EInstallReg db 'Software\FlySky\E\Install',0
EErrorMsg db '无法找到易语言支持库文件!',0
EErrorTitle db '错误',0
EStrPath db 'Path',0
EStrGetNewSock db 'GetNewSock',0
EXE_Info_Label_End:

GetExeInfoAddress proc
	lea eax,EXE_Info_Label_Start
	ret
GetExeInfoAddress endp

GetExeInfoLength proc
	mov eax,offset EXE_Info_Label_End
	sub eax,offset EXE_Info_Label_Start
	ret
GetExeInfoLength endp

GetExeInfoItem proc uses edi,ptExeInfo
	mov edi,ptExeInfo
	assume edi:ptr EXEDataInfo

	lea eax,EKrnlnName
	mov [edi].pEKrnlnName,eax

	lea eax,EInstallReg
	mov [edi].pEInstallReg,eax

	lea eax,EErrorMsg
	mov [edi].pEErrorMsg,eax

	lea eax,EErrorTitle
	mov [edi].pEErrorTitle,eax

	lea eax,EStrPath
	mov [edi].pEStrPath,eax

	lea eax,EStrGetNewSock
	mov [edi].pEStrGetNewSock,eax


	ret
GetExeInfoItem endp

EXE_Code_Label_Start:

MyEStartup proc
	local szPath[260]:byte
	local hKey
	local dwBufSize
	local hModule

	lea eax,szPath
	push eax
	call EXE_GetCurrentPath

	push offset EKrnlnName
	lea eax,szPath
	push eax
	call lstrcatA

	push eax
	call LoadLibraryA
	test eax,eax
	jnz _OnLoadSuccess

	lea eax,hKey
	push eax
	push KEY_READ
	push 0
	push offset EInstallReg
	push HKEY_CURRENT_USER
	call RegOpenKeyExA
	test eax,eax
	jnz _OnFailed

	mov dwBufSize,sizeof szPath
	lea eax,dwBufSize
	push eax
	lea eax,szPath
	push eax
	push 0
	push 0
	push offset EStrPath
	push hKey
	call RegQueryValueExA
	push eax
	push hKey
	call RegCloseKey
	pop eax
	test eax,eax
	jnz _OnFailed
	
	lea eax,szPath
	push eax
	call lstrlenA

	lea ebx,szPath
	add ebx,eax
	dec ebx
	cmp byte ptr [ebx],5Ch
	je @F
	mov word ptr [ebx],5Ch
@@:
	push offset EKrnlnName
	lea eax,szPath
	push eax
	call lstrcatA

	push eax
	call LoadLibraryA
	test eax,eax
	je _OnFailed
_OnLoadSuccess:
	mov hModule,eax


	push offset EStrGetNewSock
	push hModule
	call GetProcAddress
	test eax,eax
	je _OnFailed
	push 3E8h
	call eax
	test eax,eax
	je _OnFreeFailed

	push 12345678h
	call eax

	push 0
	call ExitProcess

_OnFreeFailed:
	push hModule
	call FreeLibrary
_OnFailed:
	push 0
	push offset EErrorTitle
	push offset EErrorMsg
	push 0
	call MessageBoxA
_Result:
	ret
MyEStartup endp


EXE_GetCurrentPath proc lpszPath
	push 80h
	push lpszPath
	push 0
	call GetModuleFileNameA
	mov ecx,lpszPath
	lea ecx,[eax+ecx-6]
@@:
	mov al,byte ptr [ecx]
	dec ecx
	cmp al,5Ch
	jnz	@B
	mov byte ptr [ecx+2],0
	ret
EXE_GetCurrentPath endp

EXE_Code_Label_End:


GetEXECodeStartAddress proc
	mov eax,offset EXE_Code_Label_Start
	ret
GetEXECodeStartAddress endp

GetEXECodeLength proc
	mov eax,offset EXE_Code_Label_End
	sub eax,offset EXE_Code_Label_Start
	ret
GetEXECodeLength endp


;------------------------------------------------------------------------------------------------------------------------------------------------------------
MyEStartup_Dll_Info_Begin:
g_hModuleInst dd 0
g_hKrnlnModule dd ?
g_pNewSockPtr dd ?
b_bLoadIndex dd -1
g_pEDllUnload dd ?

szKrnlnFnr db 'krnln.fnr',0
szELanguageInstall db 'Software\FlySky\E\Install',0
szErrorTitle db 'Error',0
szErrorText db '程序无法找到核心库文件或核心库文件无效!',0
szPathText db 'Path',0
szDllGetNewSock db 'GetNewSock',0

MyEStartup_Dll_Info_End:


DllGetDataBegin proc
	lea eax,MyEStartup_Dll_Info_Begin
	ret
DllGetDataBegin endp
DllDataInfo struct
	pg_hModuleInst dd ?
	pg_hKrnlnModule dd ?
	pg_pNewSockPtr dd ?
	pb_bLoadIndex dd ?
	pg_pEDllUnload dd ?
	pszKrnlnFnr dd ?
	pszELanguageInstall  dd ?
	pszErrorTitle dd ?
	pszErrorText dd ?
	pszPathText dd ?
	pszDllGetNewSock  dd ?
DllDataInfo ends

GetDllInfoLength proc
	mov eax,offset MyEStartup_Dll_Info_End
	sub eax,offset MyEStartup_Dll_Info_Begin
	ret
GetDllInfoLength endp
GetDllDataInfo proc uses edi,tDllDataInfo
	mov edi,tDllDataInfo
	assume edi:ptr DllDataInfo
	
	mov eax,offset g_hModuleInst
	mov [edi].pg_hModuleInst,eax

	mov eax,offset g_hKrnlnModule
	mov [edi].pg_hKrnlnModule,eax

	mov eax,offset g_pNewSockPtr
	mov [edi].pg_pNewSockPtr,eax

	mov eax,offset b_bLoadIndex
	mov [edi].pb_bLoadIndex,eax

	mov eax,offset g_pEDllUnload
	mov [edi].pg_pEDllUnload,eax

	mov eax,offset szKrnlnFnr
	mov [edi].pszKrnlnFnr,eax

	mov eax,offset szELanguageInstall
	mov [edi].pszELanguageInstall,eax

	mov eax,offset szErrorTitle
	mov [edi].pszErrorTitle,eax

	mov eax,offset szErrorText
	mov [edi].pszErrorText,eax

	mov eax,offset szPathText
	mov [edi].pszPathText,eax

	mov eax,offset szDllGetNewSock
	mov [edi].pszDllGetNewSock,eax

	ret
GetDllDataInfo endp

MyEStartup_Dll_Start:
MyEDllMain proc hModule,dwReason,lpReserved
	.if dwReason == DLL_PROCESS_ATTACH
		mov eax,hModule
		mov g_hModuleInst,eax
		call DLL_LoadKrnlnDll
		test eax,eax
		je @F
	.elseif dwReason == DLL_PROCESS_DETACH
		call DLL_FreeKrnlnDll
	.endif
@@:
	ret
MyEDllMain endp

DLL_GetCurrentPath proc lpszPath
	mov eax,g_hModuleInst
	push 80h
	push lpszPath
	push eax
	call GetModuleFileNameA
	mov ecx,lpszPath
	lea ecx,[eax+ecx-6]
@@:
	mov al,byte ptr [ecx]
	dec ecx
	cmp al,5Ch
	jnz	@B
	mov byte ptr [ecx+2],0
	ret
DLL_GetCurrentPath endp

DLL_LoadKrnlnDll proc
	local szDllPath[260]:byte
	local dwRegPathSize:dword
	local hKey:HKEY
	;取当前模块目录
	lea eax,szDllPath
	push eax
	call DLL_GetCurrentPath

	;追加字符串
	push offset szKrnlnFnr
	lea eax,szDllPath
	push eax
	call lstrcatA

	push eax
	call LoadLibraryA
	
	test eax,eax
	jnz _OnLoadSuccess

	lea eax,hKey
	push eax
	push KEY_READ
	push 0
	push offset szELanguageInstall
	push HKEY_CURRENT_USER
	call RegOpenKeyExA
	test eax,eax
	jnz NotFoundELib

	mov dwRegPathSize,sizeof szDllPath
	lea eax,dwRegPathSize
	push eax
	lea eax,szDllPath
	push eax
	push 0
	push 0
	push offset szPathText
	push hKey
	call RegQueryValueExA
	push eax
	push hKey
	call RegCloseKey
	pop eax
	test eax,eax
	jnz NotFoundELib
	lea eax,szDllPath
	push eax
	call lstrlenA
	lea ebx,szDllPath
	add ebx,eax
	dec ebx
	cmp byte ptr[ebx],5Ch
	je @F
	cmp word ptr [ebx],5Ch
@@:
	push offset szKrnlnFnr
	lea eax,szDllPath
	push eax
	call lstrcatA
	push eax
	call LoadLibraryA
	test eax,eax
	je NotFoundELib
_OnLoadSuccess:
	mov g_hKrnlnModule,eax

	push offset szDllGetNewSock
	push eax
	call GetProcAddress
	test eax,eax
	je NotFoundELib

	push eax
	push 3EAh
	call eax

	pop edx
	test eax,eax
	je NotFoundELib
	mov g_pNewSockPtr,eax
	push 3EBh
	mov ebx,offset b_bLoadIndex
	call edx
	test eax,eax
	je NotFoundELib
	mov b_bLoadIndex,edx
	push 12345678h
	call eax
	mov g_pEDllUnload,eax
	mov eax,TRUE
	jmp EndLabel
NotFoundELib:
	push MB_OK
	push offset szErrorTitle
	push offset szErrorText
	push 0
	call MessageBoxA
	xor eax,eax
EndLabel:
	ret
DLL_LoadKrnlnDll endp
	
DLL_FreeKrnlnDll proc
	mov eax,g_hKrnlnModule
	test eax,eax
	je EndLabel
	mov eax,g_pEDllUnload
	test eax,eax
	je @F
	call eax
@@:
	mov eax,g_pNewSockPtr
	test eax,eax
	je @F
	mov ecx,b_bLoadIndex
	push ecx
	call eax
@@:
	mov eax,g_hKrnlnModule
	push eax
	call FreeLibrary
EndLabel:

	mov eax,TRUE
	ret
DLL_FreeKrnlnDll endp
MyEStartup_Dll_End:



GetDllCodeStartAddress proc
	mov eax,offset MyEStartup_Dll_Start
	ret
GetDllCodeStartAddress endp

GetDllCodeLength proc
	mov eax,offset MyEStartup_Dll_End
	sub eax,offset MyEStartup_Dll_Start
	ret
GetDllCodeLength endp
end
