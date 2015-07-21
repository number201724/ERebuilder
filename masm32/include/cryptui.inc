  ; ===========================================
  ; cryptui.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CRYPTUI_INC
CRYPTUI_INC equ <1>

ACUIProviderInvokeUI PROTO :DWORD
CryptUIDlgCertMgr PROTO :DWORD
CryptUIDlgFreeCAContext PROTO :DWORD
CryptUIDlgSelectCA PROTO :DWORD
CryptUIDlgSelectC equ <CryptUIDlgSelectCA>

CryptUIDlgSelectCertificateA PROTO :DWORD
CryptUIDlgSelectCertificate equ <CryptUIDlgSelectCertificateA>

CryptUIDlgSelectCertificateFromStore PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CryptUIDlgSelectCertificateW PROTO :DWORD
CryptUIDlgSelectStoreA PROTO :DWORD
CryptUIDlgSelectStore equ <CryptUIDlgSelectStoreA>

CryptUIDlgSelectStoreW PROTO :DWORD
CryptUIDlgViewCRLA PROTO :DWORD
CryptUIDlgViewCRL equ <CryptUIDlgViewCRLA>

CryptUIDlgViewCRLW PROTO :DWORD
CryptUIDlgViewCTLA PROTO :DWORD
CryptUIDlgViewCTL equ <CryptUIDlgViewCTLA>

CryptUIDlgViewCTLW PROTO :DWORD
CryptUIDlgViewCertificateA PROTO :DWORD,:DWORD
CryptUIDlgViewCertificate equ <CryptUIDlgViewCertificateA>

CryptUIDlgViewCertificatePropertiesA PROTO :DWORD,:DWORD
CryptUIDlgViewCertificateProperties equ <CryptUIDlgViewCertificatePropertiesA>

CryptUIDlgViewCertificatePropertiesW PROTO :DWORD,:DWORD
CryptUIDlgViewCertificateW PROTO :DWORD,:DWORD
CryptUIDlgViewContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CryptUIDlgViewSignerInfoA PROTO :DWORD
CryptUIDlgViewSignerInfo equ <CryptUIDlgViewSignerInfoA>

CryptUIDlgViewSignerInfoW PROTO :DWORD
CryptUIFreeCertificatePropertiesPagesA PROTO :DWORD,:DWORD
CryptUIFreeCertificatePropertiesPages equ <CryptUIFreeCertificatePropertiesPagesA>

CryptUIFreeCertificatePropertiesPagesW PROTO :DWORD,:DWORD
CryptUIFreeViewSignaturesPagesA PROTO :DWORD,:DWORD
CryptUIFreeViewSignaturesPages equ <CryptUIFreeViewSignaturesPagesA>

CryptUIFreeViewSignaturesPagesW PROTO :DWORD,:DWORD
CryptUIGetCertificatePropertiesPagesA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CryptUIGetCertificatePropertiesPages equ <CryptUIGetCertificatePropertiesPagesA>

CryptUIGetCertificatePropertiesPagesW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CryptUIGetViewSignaturesPagesA PROTO :DWORD,:DWORD,:DWORD
CryptUIGetViewSignaturesPages equ <CryptUIGetViewSignaturesPagesA>

CryptUIGetViewSignaturesPagesW PROTO :DWORD,:DWORD,:DWORD
CryptUIStartCertMgr PROTO :DWORD,:DWORD,:DWORD,:DWORD
CryptUIWizBuildCTL PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CryptUIWizCertRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CryptUIWizCreateCertRequestNoDS PROTO :DWORD,:DWORD,:DWORD,:DWORD
CryptUIWizDigitalSign PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CryptUIWizExport PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CryptUIWizFreeCertRequestNoDS PROTO :DWORD
CryptUIWizFreeDigitalSignContext PROTO :DWORD
CryptUIWizImport PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CryptUIWizQueryCertRequestNoDS PROTO :DWORD,:DWORD
CryptUIWizSubmitCertRequestNoDS PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EnrollmentCOMObjectFactory_getInstance PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
I_CryptUIProtect PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
I_CryptUIProtectFailure PROTO :DWORD,:DWORD,:DWORD
LocalEnroll PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LocalEnrollNoDS PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RetrievePKCS7FromCA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RetrievePKCS7FromC equ <RetrievePKCS7FromCA>

WizardFree PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file cryptui.inc
echo -----------------------------------------
ENDIF
