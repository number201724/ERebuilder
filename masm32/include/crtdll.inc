; Thanx to Vortex for his work
; 
; To expand the lib definition file:
; link /DLL /def:crtdll.def /NOENTRY /subsystem:windows crtdll.obj

printf      PROTO C :DWORD, :VARARG
sprintf     PROTO C :DWORD,:DWORD, :VARARG
sscanf      PROTO C :DWORD,:DWORD, :VARARG

