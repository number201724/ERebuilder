  ; ===========================================
  ; cfgmgr.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CFGMGR_INC
CFGMGR_INC equ <1>

AddRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CMP_GetBlockedDriverInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
CMP_GetServerSideDeviceInstallFlags PROTO :DWORD,:DWORD,:DWORD
CMP_Init_Detection PROTO :DWORD
CMP_RegisterNotification PROTO :DWORD,:DWORD,:DWORD,:DWORD
CMP_Report_LogOn PROTO :DWORD,:DWORD
CMP_UnregisterNotification PROTO :DWORD
CMP_WaitNoPendingInstallEvents PROTO :DWORD
CMP_WaitServicesAvailable PROTO :DWORD
CM_Add_Empty_Log_Conf PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Add_Empty_Log_Conf_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Add_IDA PROTO :DWORD,:DWORD,:DWORD
CM_Add_ID equ <CM_Add_IDA>

CM_Add_IDW PROTO :DWORD,:DWORD,:DWORD
CM_Add_ID_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Add_ID_Ex equ <CM_Add_ID_ExA>

CM_Add_ID_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Add_Range PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Add_Res_Des PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Add_Res_Des_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Connect_MachineA PROTO :DWORD,:DWORD
CM_Connect_Machine equ <CM_Connect_MachineA>

CM_Connect_MachineW PROTO :DWORD,:DWORD
CM_Create_DevNodeA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Create_DevNode equ <CM_Create_DevNodeA>

CM_Create_DevNodeW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Create_DevNode_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Create_DevNode_Ex equ <CM_Create_DevNode_ExA>

CM_Create_DevNode_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Create_Range_List PROTO :DWORD,:DWORD
CM_Delete_Class_Key PROTO :DWORD,:DWORD
CM_Delete_Class_Key_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Delete_DevNode_Key PROTO :DWORD,:DWORD,:DWORD
CM_Delete_DevNode_Key_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Delete_Range PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Detect_Resource_Conflict PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Detect_Resource_Conflict_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Disable_DevNode PROTO :DWORD,:DWORD
CM_Disable_DevNode_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Disconnect_Machine PROTO :DWORD
CM_Dup_Range_List PROTO :DWORD,:DWORD,:DWORD
CM_Enable_DevNode PROTO :DWORD,:DWORD
CM_Enable_DevNode_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Enumerate_Classes PROTO :DWORD,:DWORD,:DWORD
CM_Enumerate_Classes_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Enumerate_EnumeratorsA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Enumerate_Enumerators equ <CM_Enumerate_EnumeratorsA>

CM_Enumerate_EnumeratorsW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Enumerate_Enumerators_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Enumerate_Enumerators_Ex equ <CM_Enumerate_Enumerators_ExA>

CM_Enumerate_Enumerators_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Find_Range PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_First_Range PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Free_Log_Conf PROTO :DWORD,:DWORD
CM_Free_Log_Conf_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Free_Log_Conf_Handle PROTO :DWORD
CM_Free_Range_List PROTO :DWORD,:DWORD
CM_Free_Res_Des PROTO :DWORD,:DWORD,:DWORD
CM_Free_Res_Des_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Free_Res_Des_Handle PROTO :DWORD
CM_Free_Resource_Conflict_Handle PROTO :DWORD
CM_Get_Child PROTO :DWORD,:DWORD,:DWORD
CM_Get_Child_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Key_NameA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Key_Name equ <CM_Get_Class_Key_NameA>

CM_Get_Class_Key_NameW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Key_Name_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Key_Name_Ex equ <CM_Get_Class_Key_Name_ExA>

CM_Get_Class_Key_Name_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_NameA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Name equ <CM_Get_Class_NameA>

CM_Get_Class_NameW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Name_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Name_Ex equ <CM_Get_Class_Name_ExA>

CM_Get_Class_Name_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Registry_PropertyA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Class_Registry_Property equ <CM_Get_Class_Registry_PropertyA>

CM_Get_Class_Registry_PropertyW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Depth PROTO :DWORD,:DWORD,:DWORD
CM_Get_Depth_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Custom_PropertyA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Custom_Property equ <CM_Get_DevNode_Custom_PropertyA>

CM_Get_DevNode_Custom_PropertyW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Custom_Property_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Custom_Property_Ex equ <CM_Get_DevNode_Custom_Property_ExA>

CM_Get_DevNode_Custom_Property_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Registry_PropertyA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Registry_Property equ <CM_Get_DevNode_Registry_PropertyA>

CM_Get_DevNode_Registry_PropertyW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Registry_Property_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Registry_Property_Ex equ <CM_Get_DevNode_Registry_Property_ExA>

CM_Get_DevNode_Registry_Property_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Status PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_DevNode_Status_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_IDA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID equ <CM_Get_Device_IDA>

CM_Get_Device_IDW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_Ex equ <CM_Get_Device_ID_ExA>

CM_Get_Device_ID_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_ListA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_List equ <CM_Get_Device_ID_ListA>

CM_Get_Device_ID_ListW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_List_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_List_Ex equ <CM_Get_Device_ID_List_ExA>

CM_Get_Device_ID_List_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_List_SizeA PROTO :DWORD,:DWORD,:DWORD
CM_Get_Device_ID_List_Size equ <CM_Get_Device_ID_List_SizeA>

CM_Get_Device_ID_List_SizeW PROTO :DWORD,:DWORD,:DWORD
CM_Get_Device_ID_List_Size_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_List_Size_Ex equ <CM_Get_Device_ID_List_Size_ExA>

CM_Get_Device_ID_List_Size_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_ID_Size PROTO :DWORD,:DWORD,:DWORD
CM_Get_Device_ID_Size_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_AliasA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_Alias equ <CM_Get_Device_Interface_AliasA>

CM_Get_Device_Interface_AliasW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_Alias_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_Alias_Ex equ <CM_Get_Device_Interface_Alias_ExA>

CM_Get_Device_Interface_Alias_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_ListA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_List equ <CM_Get_Device_Interface_ListA>

CM_Get_Device_Interface_ListW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_List_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_List_Ex equ <CM_Get_Device_Interface_List_ExA>

CM_Get_Device_Interface_List_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_List_SizeA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_List_Size equ <CM_Get_Device_Interface_List_SizeA>

CM_Get_Device_Interface_List_SizeW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_List_Size_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Device_Interface_List_Size_Ex equ <CM_Get_Device_Interface_List_Size_ExA>

CM_Get_Device_Interface_List_Size_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_First_Log_Conf PROTO :DWORD,:DWORD,:DWORD
CM_Get_First_Log_Conf_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Global_State PROTO :DWORD,:DWORD
CM_Get_Global_State_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Get_HW_Prof_FlagsA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_HW_Prof_Flags equ <CM_Get_HW_Prof_FlagsA>

CM_Get_HW_Prof_FlagsW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_HW_Prof_Flags_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_HW_Prof_Flags_Ex equ <CM_Get_HW_Prof_Flags_ExA>

CM_Get_HW_Prof_Flags_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Hardware_Profile_InfoA PROTO :DWORD,:DWORD,:DWORD
CM_Get_Hardware_Profile_Info equ <CM_Get_Hardware_Profile_InfoA>

CM_Get_Hardware_Profile_InfoW PROTO :DWORD,:DWORD,:DWORD
CM_Get_Hardware_Profile_Info_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Hardware_Profile_Info_Ex equ <CM_Get_Hardware_Profile_Info_ExA>

CM_Get_Hardware_Profile_Info_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Log_Conf_Priority PROTO :DWORD,:DWORD,:DWORD
CM_Get_Log_Conf_Priority_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Next_Log_Conf PROTO :DWORD,:DWORD,:DWORD
CM_Get_Next_Log_Conf_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Next_Res_Des PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Next_Res_Des_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Parent PROTO :DWORD,:DWORD,:DWORD
CM_Get_Parent_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Res_Des_Data PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Res_Des_Data_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Res_Des_Data_Size PROTO :DWORD,:DWORD,:DWORD
CM_Get_Res_Des_Data_Size_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Resource_Conflict_Count PROTO :DWORD,:DWORD
CM_Get_Resource_Conflict_DetailsA PROTO :DWORD,:DWORD,:DWORD
CM_Get_Resource_Conflict_Details equ <CM_Get_Resource_Conflict_DetailsA>

CM_Get_Resource_Conflict_DetailsW PROTO :DWORD,:DWORD,:DWORD
CM_Get_Sibling PROTO :DWORD,:DWORD,:DWORD
CM_Get_Sibling_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Get_Version PROTO 
CM_Get_Version_Ex PROTO :DWORD
CM_Intersect_Range_List PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Invert_Range_List PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Is_Dock_Station_Present PROTO :DWORD
CM_Is_Dock_Station_Present_Ex PROTO :DWORD,:DWORD
CM_Is_Version_Available PROTO :DWORD
CM_Is_Version_Available_Ex PROTO :DWORD,:DWORD
CM_Locate_DevNodeA PROTO :DWORD,:DWORD,:DWORD
CM_Locate_DevNode equ <CM_Locate_DevNodeA>

CM_Locate_DevNodeW PROTO :DWORD,:DWORD,:DWORD
CM_Locate_DevNode_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Locate_DevNode_Ex equ <CM_Locate_DevNode_ExA>

CM_Locate_DevNode_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Merge_Range_List PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Modify_Res_Des PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Modify_Res_Des_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Move_DevNode PROTO :DWORD,:DWORD,:DWORD
CM_Move_DevNode_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Next_Range PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Open_Class_KeyA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Open_Class_Key equ <CM_Open_Class_KeyA>

CM_Open_Class_KeyW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Open_Class_Key_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Open_Class_Key_Ex equ <CM_Open_Class_Key_ExA>

CM_Open_Class_Key_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Open_DevNode_Key PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Open_DevNode_Key_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_And_Remove_SubTreeA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_And_Remove_SubTree equ <CM_Query_And_Remove_SubTreeA>

CM_Query_And_Remove_SubTreeW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_And_Remove_SubTree_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_And_Remove_SubTree_Ex equ <CM_Query_And_Remove_SubTree_ExA>

CM_Query_And_Remove_SubTree_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_Arbitrator_Free_Data PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_Arbitrator_Free_Data_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_Arbitrator_Free_Size PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Query_Arbitrator_Free_Size_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Query_Remove_SubTree PROTO :DWORD,:DWORD
CM_Query_Remove_SubTree_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Query_Resource_Conflict_List PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Reenumerate_DevNode PROTO :DWORD,:DWORD
CM_Reenumerate_DevNode_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Register_Device_Driver PROTO :DWORD,:DWORD
CM_Register_Device_Driver_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Register_Device_InterfaceA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Register_Device_Interface equ <CM_Register_Device_InterfaceA>

CM_Register_Device_InterfaceW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Register_Device_Interface_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Register_Device_Interface_Ex equ <CM_Register_Device_Interface_ExA>

CM_Register_Device_Interface_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Remove_SubTree PROTO :DWORD,:DWORD
CM_Remove_SubTree_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Request_Device_EjectA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Request_Device_Eject equ <CM_Request_Device_EjectA>

CM_Request_Device_EjectW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Request_Device_Eject_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Request_Device_Eject_Ex equ <CM_Request_Device_Eject_ExA>

CM_Request_Device_Eject_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Request_Eject_PC PROTO 
CM_Request_Eject_PC_Ex PROTO :DWORD
CM_Run_Detection PROTO :DWORD
CM_Run_Detection_Ex PROTO :DWORD,:DWORD
CM_Set_Class_Registry_PropertyA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Set_Class_Registry_Property equ <CM_Set_Class_Registry_PropertyA>

CM_Set_Class_Registry_PropertyW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Set_DevNode_Problem PROTO :DWORD,:DWORD,:DWORD
CM_Set_DevNode_Problem_Ex PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Set_DevNode_Registry_PropertyA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Set_DevNode_Registry_Property equ <CM_Set_DevNode_Registry_PropertyA>

CM_Set_DevNode_Registry_PropertyW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Set_DevNode_Registry_Property_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Set_DevNode_Registry_Property_Ex equ <CM_Set_DevNode_Registry_Property_ExA>

CM_Set_DevNode_Registry_Property_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Set_HW_Prof PROTO :DWORD,:DWORD
CM_Set_HW_Prof_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Set_HW_Prof_FlagsA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Set_HW_Prof_Flags equ <CM_Set_HW_Prof_FlagsA>

CM_Set_HW_Prof_FlagsW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CM_Set_HW_Prof_Flags_ExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Set_HW_Prof_Flags_Ex equ <CM_Set_HW_Prof_Flags_ExA>

CM_Set_HW_Prof_Flags_ExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Setup_DevNode PROTO :DWORD,:DWORD
CM_Setup_DevNode_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Test_Range_Available PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CM_Uninstall_DevNode PROTO :DWORD,:DWORD
CM_Uninstall_DevNode_Ex PROTO :DWORD,:DWORD,:DWORD
CM_Unregister_Device_InterfaceA PROTO :DWORD,:DWORD
CM_Unregister_Device_Interface equ <CM_Unregister_Device_InterfaceA>

CM_Unregister_Device_InterfaceW PROTO :DWORD,:DWORD
CM_Unregister_Device_Interface_ExA PROTO :DWORD,:DWORD,:DWORD
CM_Unregister_Device_Interface_Ex equ <CM_Unregister_Device_Interface_ExA>

CM_Unregister_Device_Interface_ExW PROTO :DWORD,:DWORD,:DWORD
CfgmgrEntry PROTO :DWORD,:DWORD,:DWORD
ClearRanges PROTO :DWORD
Convert32bitResDesSizeTo64bitResDesSize PROTO :DWORD,:DWORD
Convert32bitResDesTo64bitResDes PROTO :DWORD,:DWORD,:DWORD
CopyFixedUpDeviceId PROTO :DWORD,:DWORD,:DWORD
CopyRanges PROTO :DWORD,:DWORD
CreateLogConfHandle PROTO :DWORD,:DWORD,:DWORD,:DWORD
CreateResDesHandle PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DeletePrivateKey PROTO :DWORD,:DWORD,:DWORD
DeleteRange PROTO :DWORD
DestroyPrivateResource PROTO :DWORD
EnablePnPPrivileges PROTO 
FreeConfListHandle PROTO :DWORD
Get32bitResDesFrom64bitResDes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetDevNodeKeyPath PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetPropertyDataType PROTO :DWORD
INVALID_DEVINST PROTO :DWORD
I_RpcExceptionFilter PROTO :DWORD
I_ScPnPGetServiceName PROTO :DWORD,:DWORD,:DWORD
InitPrivateResource PROTO :DWORD
InsertRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IsLegalDeviceId PROTO :DWORD
IsRemoteServiceRunning PROTO :DWORD,:DWORD
IsValidRangeList PROTO :DWORD
JoinRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LockPrivateResource PROTO :DWORD
MIDL_user_allocate PROTO :DWORD
MIDL_user_free PROTO :DWORD
MapRpcExceptionToCR PROTO :DWORD
PNP_AddEmptyLogConf PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_AddID PROTO :DWORD,:DWORD,:DWORD,:DWORD
PNP_AddResDes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_Connect PROTO :DWORD
PNP_CreateDevInst PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_CreateKey PROTO :DWORD,:DWORD,:DWORD,:DWORD
PNP_DeleteClassKey PROTO :DWORD,:DWORD,:DWORD
PNP_DeleteRegistryKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_DetectResourceConflict PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_DeviceInstanceAction PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_DisableDevInst PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_Disconnect PROTO :DWORD
PNP_EnumerateSubKeys PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_FreeLogConf PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_FreeResDes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetBlockedDriverInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetClassCount PROTO :DWORD,:DWORD,:DWORD
PNP_GetClassInstance PROTO :DWORD,:DWORD,:DWORD,:DWORD
PNP_GetClassName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetClassRegProp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetCustomDevProp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetDepth PROTO :DWORD,:DWORD,:DWORD,:DWORD
PNP_GetDeviceList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetDeviceListSize PROTO :DWORD,:DWORD,:DWORD,:DWORD
PNP_GetDeviceRegProp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetDeviceStatus PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetFirstLogConf PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetGlobalState PROTO :DWORD,:DWORD,:DWORD
PNP_GetHwProfInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetInterfaceDeviceAlias PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetInterfaceDeviceList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetInterfaceDeviceListSize PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetLogConfPriority PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetNextLogConf PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetNextResDes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetRelatedDeviceInstance PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetResDesData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetResDesDataSize PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_GetRootDeviceInstance PROTO :DWORD,:DWORD,:DWORD
PNP_GetServerSideDeviceInstallFlags PROTO :DWORD,:DWORD,:DWORD
PNP_GetVersion PROTO :DWORD,:DWORD
PNP_GetVersionInternal PROTO :DWORD,:DWORD
PNP_HANDLE_bind PROTO :DWORD
PNP_HANDLE_unbind PROTO :DWORD,:DWORD
PNP_HwProfFlags PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_InitDetection PROTO :DWORD
PNP_IsDockStationPresent PROTO :DWORD,:DWORD
PNP_ModifyResDes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_QueryArbitratorFreeData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_QueryArbitratorFreeSize PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_QueryRemove PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_QueryResConfList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_RegisterDeviceClassAssociation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_RegisterDriver PROTO :DWORD,:DWORD,:DWORD
PNP_RegisterNotification PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_ReportLogOn PROTO :DWORD,:DWORD,:DWORD
PNP_RequestDeviceEject PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_RequestEjectPC PROTO :DWORD
PNP_RunDetection PROTO :DWORD,:DWORD
PNP_SetClassRegProp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_SetDeviceProblem PROTO :DWORD,:DWORD,:DWORD,:DWORD
PNP_SetDeviceRegProp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PNP_SetHwProf PROTO :DWORD,:DWORD,:DWORD
PNP_UninstallDevInst PROTO :DWORD,:DWORD,:DWORD
PNP_UnregisterDeviceClassAssociation PROTO :DWORD,:DWORD,:DWORD
PNP_UnregisterNotification PROTO :DWORD,:DWORD
PNP_ValidateDeviceInstance PROTO :DWORD,:DWORD,:DWORD
PnPGetGlobalHandles PROTO :DWORD,:DWORD,:DWORD
PnPGetVersion PROTO :DWORD,:DWORD
PnPMultiByteToUnicode PROTO :DWORD,:DWORD,:DWORD,:DWORD
PnPRetrieveMachineName PROTO :DWORD,:DWORD
PnPUnicodeToMultiByte PROTO :DWORD,:DWORD,:DWORD,:DWORD
RpcpBindRpc PROTO :DWORD,:DWORD,:DWORD,:DWORD
RpcpUnbindRpc PROTO :DWORD
TestRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
UnlockPrivateResource PROTO :DWORD
ValidateConfListHandle PROTO :DWORD
ValidateLogConfHandle PROTO :DWORD
ValidateResDesHandle PROTO :DWORD
_PNP_AddEmptyLogConf PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD
pSetupCaptureAndConvertAnsiArg PROTO :DWORD,:DWORD
pSetupConvertSDToText PROTO :DWORD,:DWORD
pSetupConvertTextToSD PROTO :DWORD,:DWORD
pSetupFree PROTO :DWORD
pSetupGuidFromString PROTO :DWORD,:DWORD
pSetupIsUserAdmin PROTO 
pSetupMalloc PROTO :DWORD
pSetupRealloc PROTO :DWORD,:DWORD
pSetupStringFromGuid PROTO :DWORD,:DWORD,:DWORD
pSetupStringTableAddString PROTO :DWORD,:DWORD,:DWORD
pSetupStringTableDestroy PROTO :DWORD
pSetupStringTableInitialize PROTO 
pSetupStringTableStringFromIdEx PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file cfgmgr.inc
echo -----------------------------------------
ENDIF
