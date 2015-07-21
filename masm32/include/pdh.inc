  ; ===========================================
  ; pdh.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF PDH_INC
PDH_INC equ <1>

PdhAddCounterA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhAddCounter equ <PdhAddCounterA>

PdhAddCounterW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhBindInputDataSourceA PROTO :DWORD,:DWORD
PdhBindInputDataSource equ <PdhBindInputDataSourceA>

PdhBindInputDataSourceW PROTO :DWORD,:DWORD
PdhBrowseCountersA PROTO :DWORD
PdhBrowseCounters equ <PdhBrowseCountersA>

PdhBrowseCountersHA PROTO :DWORD
PdhBrowseCountersH equ <PdhBrowseCountersHA>

PdhBrowseCountersHW PROTO :DWORD
PdhBrowseCountersW PROTO :DWORD
PdhCalculateCounterFromRawValue PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhCloseLog PROTO :DWORD,:DWORD
PdhCloseQuery PROTO :DWORD
PdhCollectQueryData PROTO :DWORD
PdhCollectQueryDataEx PROTO :DWORD,:DWORD,:DWORD
PdhComputeCounterStatistics PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhConnectMachineA PROTO :DWORD
PdhConnectMachine equ <PdhConnectMachineA>

PdhConnectMachineW PROTO :DWORD
PdhCreateSQLTablesA PROTO :DWORD
PdhCreateSQLTables equ <PdhCreateSQLTablesA>

PdhCreateSQLTablesW PROTO :DWORD
PdhEnumLogSetNamesA PROTO :DWORD,:DWORD,:DWORD
PdhEnumLogSetNames equ <PdhEnumLogSetNamesA>

PdhEnumLogSetNamesW PROTO :DWORD,:DWORD,:DWORD
PdhEnumMachinesA PROTO :DWORD,:DWORD,:DWORD
PdhEnumMachines equ <PdhEnumMachinesA>

PdhEnumMachinesHA PROTO :DWORD,:DWORD,:DWORD
PdhEnumMachinesH equ <PdhEnumMachinesHA>

PdhEnumMachinesHW PROTO :DWORD,:DWORD,:DWORD
PdhEnumMachinesW PROTO :DWORD,:DWORD,:DWORD
PdhEnumObjectItemsA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhEnumObjectItems equ <PdhEnumObjectItemsA>

PdhEnumObjectItemsHA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhEnumObjectItemsH equ <PdhEnumObjectItemsHA>

PdhEnumObjectItemsHW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhEnumObjectItemsW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhEnumObjectsA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhEnumObjects equ <PdhEnumObjectsA>

PdhEnumObjectsHA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhEnumObjectsH equ <PdhEnumObjectsHA>

PdhEnumObjectsHW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhEnumObjectsW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhExpandCounterPathA PROTO :DWORD,:DWORD,:DWORD
PdhExpandCounterPath equ <PdhExpandCounterPathA>

PdhExpandCounterPathW PROTO :DWORD,:DWORD,:DWORD
PdhExpandWildCardPathA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhExpandWildCardPath equ <PdhExpandWildCardPathA>

PdhExpandWildCardPathHA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhExpandWildCardPathH equ <PdhExpandWildCardPathHA>

PdhExpandWildCardPathHW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhExpandWildCardPathW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhFormatFromRawValue PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhGetCounterInfoA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetCounterInfo equ <PdhGetCounterInfoA>

PdhGetCounterInfoW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetCounterTimeBase PROTO :DWORD,:DWORD
PdhGetDataSourceTimeRangeA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetDataSourceTimeRange equ <PdhGetDataSourceTimeRangeA>

PdhGetDataSourceTimeRangeH PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetDataSourceTimeRangeW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfCounterA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfCounter equ <PdhGetDefaultPerfCounterA>

PdhGetDefaultPerfCounterHA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfCounterH equ <PdhGetDefaultPerfCounterHA>

PdhGetDefaultPerfCounterHW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfCounterW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfObjectA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfObject equ <PdhGetDefaultPerfObjectA>

PdhGetDefaultPerfObjectHA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfObjectH equ <PdhGetDefaultPerfObjectHA>

PdhGetDefaultPerfObjectHW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetDefaultPerfObjectW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetDllVersion PROTO :DWORD
PdhGetFormattedCounterArrayA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhGetFormattedCounterArray equ <PdhGetFormattedCounterArrayA>

PdhGetFormattedCounterArrayW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhGetFormattedCounterValue PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetLogFileSize PROTO :DWORD,:DWORD
PdhGetLogSetGUID PROTO :DWORD,:DWORD,:DWORD
PdhGetRawCounterArrayA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetRawCounterArray equ <PdhGetRawCounterArrayA>

PdhGetRawCounterArrayW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhGetRawCounterValue PROTO :DWORD,:DWORD,:DWORD
PdhIsRealTimeQuery PROTO :DWORD
PdhLogServiceCommandA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhLogServiceCommand equ <PdhLogServiceCommandA>

PdhLogServiceCommandW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhLogServiceControlA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhLogServiceControl equ <PdhLogServiceControlA>

PdhLogServiceControlW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhLookupPerfIndexByNameA PROTO :DWORD,:DWORD,:DWORD
PdhLookupPerfIndexByName equ <PdhLookupPerfIndexByNameA>

PdhLookupPerfIndexByNameW PROTO :DWORD,:DWORD,:DWORD
PdhLookupPerfNameByIndexA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhLookupPerfNameByIndex equ <PdhLookupPerfNameByIndexA>

PdhLookupPerfNameByIndexW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhMakeCounterPathA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhMakeCounterPath equ <PdhMakeCounterPathA>

PdhMakeCounterPathW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhOpenLogA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhOpenLog equ <PdhOpenLogA>

PdhOpenLogW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhOpenQueryA PROTO :DWORD,:DWORD,:DWORD
PdhOpenQuery equ <PdhOpenQueryA>

PdhOpenQueryH PROTO :DWORD,:DWORD,:DWORD
PdhOpenQueryW PROTO :DWORD,:DWORD,:DWORD
PdhParseCounterPathA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhParseCounterPath equ <PdhParseCounterPathA>

PdhParseCounterPathW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhParseInstanceNameA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhParseInstanceName equ <PdhParseInstanceNameA>

PdhParseInstanceNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhReadRawLogRecord PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhRemoveCounter PROTO :DWORD
PdhSelectDataSourceA PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhSelectDataSource equ <PdhSelectDataSourceA>

PdhSelectDataSourceW PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhSetCounterScaleFactor PROTO :DWORD,:DWORD
PdhSetDefaultRealTimeDataSource PROTO :DWORD
PdhSetLogSetRunID PROTO :DWORD,:DWORD
PdhSetQueryTimeRange PROTO :DWORD,:DWORD
PdhUpdateLogA PROTO :DWORD,:DWORD
PdhUpdateLog equ <PdhUpdateLogA>

PdhUpdateLogFileCatalog PROTO :DWORD
PdhUpdateLogW PROTO :DWORD,:DWORD
PdhValidatePathA PROTO :DWORD
PdhValidatePath equ <PdhValidatePathA>

PdhValidatePathW PROTO :DWORD
PdhVbAddCounter PROTO :DWORD,:DWORD,:DWORD
PdhVbCreateCounterPathList PROTO :DWORD,:DWORD
PdhVbGetCounterPathElements PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhVbGetCounterPathFromList PROTO :DWORD,:DWORD,:DWORD
PdhVbGetDoubleCounterValue PROTO :DWORD,:DWORD
PdhVbGetLogFileSize PROTO :DWORD,:DWORD
PdhVbGetOneCounterPath PROTO :DWORD,:DWORD,:DWORD,:DWORD
PdhVbIsGoodStatus PROTO :DWORD
PdhVbOpenLog PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PdhVbOpenQuery PROTO :DWORD
PdhVbUpdateLog PROTO :DWORD,:DWORD
PdhVerifySQLDBA PROTO :DWORD
PdhVerifySQLDB equ <PdhVerifySQLDBA>

PdhVerifySQLDBW PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file pdh.inc
echo -----------------------------------------
ENDIF
