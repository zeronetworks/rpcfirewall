// EventSink.cpp
#include "stdafx.h"
#include "EventSink.h"
#include "common.h"
#include "Injections.h"

ULONG EventSink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

ULONG EventSink::Release()
{
    LONG lRef = InterlockedDecrement(&m_lRef);
    if (lRef == 0)
        delete this;
    return lRef;
}

HRESULT EventSink::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink*)this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    else return E_NOINTERFACE;
}


HRESULT EventSink::Indicate(long lObjectCount,
    IWbemClassObject** apObjArray)
{
    HRESULT hres = S_OK;
    _variant_t vtProp;

    for (int i = 0; i < lObjectCount; i++)
    {
        //VARIANT v;
        _variant_t var_val;
        hres = apObjArray[i]->Get(L"TargetInstance", 0, &vtProp, 0, 0);
        if (!FAILED(hres))
        {
            IUnknown* str = vtProp;
            hres = str->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&apObjArray[i]));
            if (!FAILED(hres))
            {
                _variant_t cn;
                hres = apObjArray[i]->Get(L"ProcessId", 0, &cn, NULL, NULL);
                if (!FAILED(hres))
                {
                    if ((cn.vt != VT_NULL) || (cn.vt != VT_EMPTY))
                    {
                        outputMessage(L"New process detected", cn.uintVal);
                        crawlProcesses(cn.uintVal);
                    }
                }
                VariantClear(&cn);
            }
            VariantClear(&vtProp);
        }
    }

    return WBEM_S_NO_ERROR;
}

HRESULT EventSink::SetStatus(
    /* [in] */ LONG lFlags,
    /* [in] */ HRESULT hResult,
    /* [in] */ BSTR strParam,
    /* [in] */ IWbemClassObject __RPC_FAR* pObjParam
)
{
    if (lFlags == WBEM_STATUS_COMPLETE)
    {
        _tprintf(_T("Call complete. hResult = 0x%X\n"), hResult);
    }
    else if (lFlags == WBEM_STATUS_PROGRESS)
    {
        _tprintf(_T("Call in progress.\n"));
    }

    return WBEM_S_NO_ERROR;
}    // end of EventSink.cpp

wmiEventRegistrant::wmiEventRegistrant() 
{
    this->pSink = new EventSink; 
}

wmiEventRegistrant::~wmiEventRegistrant()
{
    HRESULT hres;
    hres = pSvc->CancelAsyncCall(pStubSink);

    this->pSvc->Release();
    this->pLoc->Release();
    this->pUnsecApp->Release();
    this->pStubUnk->Release();
    this->pSink->Release();
    this->pStubSink->Release();
    CoUninitialize();

}

bool wmiEventRegistrant::registerForProcessCreatedEvents()
{
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        _tprintf(_T("Failed to initialize COM library. Error code = 0x%x\n"), hres);
        return false;
    }

    // Set general COM security levels --------------------------
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {
        _tprintf(_T("Failed to initialize security. Error code = 0x%x\n"), hres);
        CoUninitialize();
        return false;
    }

    // Obtain the initial locator to WMI 

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        _tprintf(_T("Failed to create IWbemLocator object. Err code = 0x%x\n"), hres);
        CoUninitialize();
        return false;                 // Program has failed.
    }


    // Connect to the local root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres))
    {
        _tprintf(_T("Could not connect. Error code = 0x%x\n"), hres);
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    _tprintf(_T("Connected to ROOT\\CIMV2 WMI namespace\n"));


    // Set security levels on the proxy 

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        _tprintf(_T("Could not set proxy blanket. Error code = 0x%x\n"), hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Receive event notifications 

    hres = CoCreateInstance(CLSID_UnsecuredApartment, NULL,
        CLSCTX_LOCAL_SERVER, IID_IUnsecuredApartment,
        (void**)&pUnsecApp);

    pSink->AddRef();

    pUnsecApp->CreateObjectStub(pSink, &pStubUnk);

    pStubUnk->QueryInterface(IID_IWbemObjectSink,
        (void**)&pStubSink);

    // The ExecNotificationQueryAsync method will call
    // The EventQuery::Indicate method when an event occurs
    hres = pSvc->ExecNotificationQueryAsync(_bstr_t("WQL"), _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        pStubSink);

    // Check for errors.
    if (FAILED(hres))
    {
        printf("ExecNotificationQueryAsync failed "
            "with = 0x%X\n", hres);
        pSvc->Release();
        pLoc->Release();
        pUnsecApp->Release();
        pStubUnk->Release();
        pSink->Release();
        pStubSink->Release();
        CoUninitialize();
        return false;
    }

    return true;
}
