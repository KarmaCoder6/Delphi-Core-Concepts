unit WinCryptAPI;

interface

uses
  Winapi.Windows, Soap.Win.CertHelper;

const
  CALG_3DES =	$00006603;
  CALG_3DES_112 =	$00006609;
  CALG_SHA1	= $00008004;
  CALG_SHA_256 = $0000800c;
  CALG_SHA_512 = $0000800e;
  CALG_AES_256 = $00006610;
  PROV_RSA_SCHANNEL = 12;
  PROV_RSA_AES = 24;
  CRYPT_VERIFYCONTEXT = $F0000000;
  CRYPT_SILENT = $00000040;
  HP_HASHVAL = 2;
  HP_HASHSIZE = 4;
  KP_KEYLEN = 9;

  CERT_STORE_CERTIFICATE_CONTEXT   = 1;
  CERT_STORE_CRL_CONTEXT   = 2;
  CERT_STORE_CTL_CONTEXT   = 3;

  USAGE_MATCH_TYPE_AND = 0;
  USAGE_MATCH_TYPE_OR  = 1;

  CERT_TRUST_NO_ERROR                             = $00000000;
  CERT_TRUST_IS_NOT_TIME_VALID                    = $00000001;
  CERT_TRUST_IS_NOT_TIME_NESTED                   = $00000002;
  CERT_TRUST_IS_REVOKED                           = $00000004;
  CERT_TRUST_IS_NOT_SIGNATURE_VALID               = $00000008;
  CERT_TRUST_IS_NOT_VALID_FOR_USAGE               = $00000010;
  CERT_TRUST_IS_UNTRUSTED_ROOT                    = $00000020;
  CERT_TRUST_REVOCATION_STATUS_UNKNOWN            = $00000040;
  CERT_TRUST_IS_CYCLIC                            = $00000080;
  CERT_TRUST_INVALID_EXTENSION                    = $00000100;
  CERT_TRUST_INVALID_POLICY_CONSTRAINTS           = $00000200;
  CERT_TRUST_INVALID_BASIC_CONSTRAINTS            = $00000400;
  CERT_TRUST_INVALID_NAME_CONSTRAINTS             = $00000800;
  CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT    = $00001000;
  CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT      = $00002000;
  CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT    = $00004000;
  CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT         = $00008000;
  CERT_TRUST_IS_OFFLINE_REVOCATION                = $01000000;
  CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY             = $02000000;
  CERT_TRUST_IS_PARTIAL_CHAIN                     = $00010000;
  CERT_TRUST_CTL_IS_NOT_TIME_VALID                = $00020000;
  CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID           = $00040000;
  CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE           = $00080000;

  CERT_TRUST_HAS_EXACT_MATCH_ISSUER               = $00000001;
  CERT_TRUST_HAS_KEY_MATCH_ISSUER                 = $00000002;
  CERT_TRUST_HAS_NAME_MATCH_ISSUER                = $00000004;
  CERT_TRUST_IS_SELF_SIGNED                       = $00000008;

  CERT_TRUST_HAS_PREFERRED_ISSUER                 = $00000100;
  CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY            = $00000200;
  CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS           = $00000400;

  CERT_TRUST_IS_COMPLEX_CHAIN                     = $00010000;

  szOID_TRUSTED_SERVER_AUTH_CA_LIST = '1.3.6.1.4.1.311.2.2.3';

type
  HCRYPTPROV = type THandle;
  ALG_ID = type DWORD;
  HCRYPTKEY = type THandle;
  HCRYPTHASH = type THandle;
  HCERTCHAINENGINE = type THandle;
  HCRYPTMSG = Pointer;

  CTL_USAGE = record
    cUsageIdentifier: DWORD;
    rgpszUsageIdentifier: ^LPSTR; // array of pszObjId
  end;
  PCTL_USAGE = ^CTL_USAGE;
  CERT_ENHKEY_USAGE = CTL_USAGE;
  PCERT_ENHKEY_USAGE = ^CERT_ENHKEY_USAGE;

  CERT_USAGE_MATCH = record
    dwType: DWORD;
    Usage: CERT_ENHKEY_USAGE;
  end;
  PCERT_USAGE_MATCH = ^CERT_USAGE_MATCH;

  CERT_STRONG_SIGN_SERIALIZED_INFO = record
    dwFlags: DWORD;
    pwszCNGSignHashAlgids: LPWSTR;
    pwszCNGPubKeyMinBitLengths: LPWSTR;
  end;
  PCERT_STRONG_SIGN_SERIALIZED_INFO = ^CERT_STRONG_SIGN_SERIALIZED_INFO;

  CERT_STRONG_SIGN_PARA = record
    cbSize: DWORD;
    dwInfoChoice: DWORD;
    case Byte of
      1: (pvInfo: Pointer);
      2: (pSerializedInfo: PCERT_STRONG_SIGN_SERIALIZED_INFO);
      3: (pszOID: LPSTR);
  end;
  PCERT_STRONG_SIGN_PARA = ^CERT_STRONG_SIGN_PARA;
  PCCERT_STRONG_SIGN_PARA = PCERT_STRONG_SIGN_PARA;

  CERT_CHAIN_PARA = record
    cbSize: DWORD;
    RequestedUsage: CERT_USAGE_MATCH;
    RequestedIssuancePolicy: CERT_USAGE_MATCH;
    dwUrlRetrievalTimeout: DWORD;
    fCheckRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;
    pftCacheResync: PFileTime;
    pStrongSignPara: PCCERT_STRONG_SIGN_PARA;
    dwStrongSignFlags: DWORD;
  end;
  PCERT_CHAIN_PARA = ^CERT_CHAIN_PARA;

  CRYPTOAPI_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;

  CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_INTEGER_BLOB = ^CRYPT_INTEGER_BLOB;
  CRYPT_UINT_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_UINT_BLOB = ^CRYPT_UINT_BLOB;
  CRYPT_OBJID_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_OBJID_BLOB = ^CRYPT_OBJID_BLOB;
  CERT_NAME_BLOB = CRYPTOAPI_BLOB;
  PCERT_NAME_BLOB = ^CERT_NAME_BLOB;
  CERT_RDN_VALUE_BLOB = CRYPTOAPI_BLOB;
  PCERT_RDN_VALUE_BLOB = ^CERT_RDN_VALUE_BLOB;
  CERT_BLOB = CRYPTOAPI_BLOB;
  PCERT_BLOB = ^CERT_BLOB;
  CRL_BLOB = CRYPTOAPI_BLOB;
  PCRL_BLOB = ^CRL_BLOB;
  DATA_BLOB = CRYPTOAPI_BLOB;
  PDATA_BLOB = ^DATA_BLOB;
  CRYPT_DATA_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_DATA_BLOB = ^CRYPT_DATA_BLOB;
  CRYPT_HASH_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_HASH_BLOB = ^CRYPT_HASH_BLOB;
  CRYPT_DIGEST_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_DIGEST_BLOB = ^CRYPT_DIGEST_BLOB;
  CRYPT_DER_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_DER_BLOB = ^CRYPT_DER_BLOB;
  CRYPT_ATTR_BLOB = CRYPTOAPI_BLOB;
  PCRYPT_ATTR_BLOB = ^CRYPT_ATTR_BLOB;

  CRYPT_ATTRIBUTE = record
    pszObjId: LPSTR;
    cValue: DWORD;
    rgValue: PCRYPT_ATTR_BLOB;
  end;
  PCRYPT_ATTRIBUTE = ^CRYPT_ATTRIBUTE;

  CTL_ENTRY = record
    SubjectIdentifier: CRYPT_DATA_BLOB;          // For example, its hash
    cAttribute: DWORD;
    rgAttribute: PCRYPT_ATTRIBUTE;
  end;
  PCTL_ENTRY = ^CTL_ENTRY;

  CTL_INFO = record
    dwVersion: DWORD;
    SubjectUsage: CTL_USAGE;
    ListIdentifier: CRYPT_DATA_BLOB;
    SequenceNumber: CRYPT_INTEGER_BLOB;
    ThisUpdate: TFileTime;
    NextUpdate: TFileTime;
    SubjectAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    cCTLEntry: DWORD;
    rgCTLEntry: PCTL_ENTRY;
    cExtension: DWORD;
    rgExtension: PCERT_EXTENSION;
  end;
  PCTL_INFO = ^CTL_INFO;

  CTL_CONTEXT = record
    dwMsgAndCertEncodingType: DWORD;
    pbCtlEncoded: PByte;
    cbCtlEncoded: DWORD;
    pCtlInfo: PCTL_INFO;
    hCertStore: HCERTSTORE;
    hCryptMsg: HCRYPTMSG;
    pbCtlContent: PByte;
    cbCtlContent: DWORD;
  end;
  PCTL_CONTEXT = ^CTL_CONTEXT;
  PCCTL_CONTEXT = PCTL_CONTEXT;

  CERT_TRUST_LIST_INFO = record
    cbSize: DWORD;
    pCtlEntry: PCTL_ENTRY;
    pCtlContext: PCCTL_CONTEXT;
  end;
  PCERT_TRUST_LIST_INFO = ^CERT_TRUST_LIST_INFO;

  CERT_TRUST_STATUS = record
    dwErrorStatus: DWORD;
    dwInfoStatus: DWORD;
  end;
  PCERT_TRUST_STATUS = ^CERT_TRUST_STATUS;

  CRL_ENTRY = record
    SerialNumber: CRYPT_INTEGER_BLOB;
    RevocationDate: TFileTime;
    cExtension: DWORD;
    rgExtension: PCERT_EXTENSION;
  end;
  PCRL_ENTRY = ^CRL_ENTRY;

  CRL_INFO = record
    dwVersion: DWORD;
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    Issuer: CERT_NAME_BLOB;
    ThisUpdate: TFileTime;
    NextUpdate: TFileTime;
    cCRLEntry: DWORD;
    rgCRLEntry: PCRL_ENTRY;
    cExtension: DWORD;
    rgExtension: PCERT_EXTENSION;
  end;
  PCRL_INFO = ^CRL_INFO;

  CRL_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCrlEncoded: PByte;
    cbCrlEncoded: DWORD;
    pCrlInfo: PCRL_INFO;
    hCertStore: HCERTSTORE;
  end;
  PCRL_CONTEXT = ^CRL_CONTEXT;
  PCCRL_CONTEXT = PCRL_CONTEXT;

  CERT_REVOCATION_CRL_INFO = record
    cbSize: DWORD;
    pBaseCrlContext: PCCRL_CONTEXT;
    pDeltaCrlContext: PCCRL_CONTEXT;
    pCrlEntry: PCRL_ENTRY;
    fDeltaCrlEntry: BOOL; // TRUE if in pDeltaCrlContext
  end;
  PCERT_REVOCATION_CRL_INFO = ^CERT_REVOCATION_CRL_INFO;

  CERT_REVOCATION_INFO = record
    cbSize: DWORD;
    dwRevocationResult: DWORD;
    pszRevocationOid: LPCSTR;
    pvOidSpecificInfo: LPVOID;
    fHasFreshnessTime: BOOL;
    dwFreshnessTime: DWORD;    // seconds
    pCrlInfo: PCERT_REVOCATION_CRL_INFO;
  end;
  PCERT_REVOCATION_INFO = ^CERT_REVOCATION_INFO;

  CERT_CHAIN_ELEMENT = record
    cbSize: DWORD;
    pCertContext: PCCERT_CONTEXT;
    TrustStatus: CERT_TRUST_STATUS;
    pRevocationInfo: PCERT_REVOCATION_INFO;
    pIssuanceUsage: PCERT_ENHKEY_USAGE;       // If NULL, any
    pApplicationUsage: PCERT_ENHKEY_USAGE;    // If NULL, any
    pwszExtendedErrorInfo: LPCWSTR;    // If NULL, none
  end;
  PCERT_CHAIN_ELEMENT = ^CERT_CHAIN_ELEMENT;

  CERT_SIMPLE_CHAIN = record
    cbSize: DWORD;
    TrustStatus: CERT_TRUST_STATUS;
    cElement: DWORD;
    rgpElement: ^PCERT_CHAIN_ELEMENT;
    pTrustListInfo: PCERT_TRUST_LIST_INFO;
    fHasRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;    // seconds
  end;
  PCERT_SIMPLE_CHAIN = ^CERT_SIMPLE_CHAIN;

  PPCCERT_CHAIN_CONTEXT_ = Pointer; // Cast to PPCCERT_CHAIN_CONTEXT

  CERT_CHAIN_CONTEXT = record
    cbSize: DWORD;
    TrustStatus: CERT_TRUST_STATUS;
    cChain: DWORD;
    rgpChain: ^PCERT_SIMPLE_CHAIN;
    cLowerQualityChainContext: DWORD;
    rgpLowerQualityChainContext: PPCCERT_CHAIN_CONTEXT_;
    fHasRevocationFreshnessTime: BOOL;
    dwRevocationFreshnessTime: DWORD;    // seconds
  end;

  PCERT_CHAIN_CONTEXT = ^CERT_CHAIN_CONTEXT;
  PCCERT_CHAIN_CONTEXT = PCERT_CHAIN_CONTEXT;
  PPCCERT_CHAIN_CONTEXT = ^PCCERT_CHAIN_CONTEXT;

const
  HCCE_CURRENT_USER = HCERTCHAINENGINE(0);
  HCCE_LOCAL_MACHINE = HCERTCHAINENGINE(1);

function CryptAcquireContext(out phProv: HCRYPTPROV; pszContainer: LPCTSTR; pszProvider: LPCTSTR;
  dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall; external advapi32 name 'CryptAcquireContextW';

function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall; external advapi32;

function CryptCreateHash(hProv: HCRYPTPROV; Algid: ALG_ID; hKey: HCRYPTKEY; dwFlags: DWORD;
  out phHash: HCRYPTHASH): BOOL; stdcall; external advapi32;

function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall; external advapi32;

function CryptHashData(hHash: HCRYPTHASH; pbData: PByte; dwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall; external advapi32;

function CryptGetHashParam(hHash: HCRYPTHASH; dwParam: DWORD; pbData: PByte;
         var pdwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall; external advapi32;

function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: PByte): BOOL; stdcall; external advapi32;

function CryptGenKey(hProv: HCRYPTPROV; Algid: ALG_ID; dwFlags: DWORD; out phKey: HCRYPTKEY): BOOL; stdcall; external advapi32;

function CryptEncrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; _Final: BOOL; dwFlags: DWORD; pbData: PByte;
         var pdwDataLen: DWORD; dwBufLen: DWORD): BOOL; stdcall; external advapi32;

function CryptGetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pbData: PByte; var pdwDataLen: DWORD;
                          dwFlags: DWORD): BOOL; stdcall; external advapi32;

function CryptSetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pbData: PByte; dwFlags: DWORD): BOOL; stdcall; external advapi32;

function CryptDeriveKey(hProv: HCRYPTPROV; Algid: ALG_ID; hBaseData: HCRYPTHASH;
        dwFlags: DWORD; var phKey: HCRYPTKEY): BOOL; stdcall; external advapi32;

function CertVerifyTimeValidity(pTimeToVerify: PFileTime; pCertInfo: PCERT_INFO): LONG; stdcall; external 'Crypt32.dll';

function CertGetCertificateChain(
  hChainEngine: HCERTCHAINENGINE;
  pCertContext: PCCERT_CONTEXT;
  pTime: PFileTime;
  hAdditionalStore: HCERTSTORE;
  pChainPara: PCERT_CHAIN_PARA;
  dwFlags: DWORD;
  pvReserved: LPVOID;
  var ppChainContext: PCCERT_CHAIN_CONTEXT): BOOL; stdcall; external 'Crypt32.dll';

procedure CertFreeCertificateChain(pChainContext: PCCERT_CHAIN_CONTEXT); stdcall; external 'Crypt32.dll';

implementation

end.
