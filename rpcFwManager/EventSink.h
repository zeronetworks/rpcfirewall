#pragma once
#ifndef EVENTSINK_H
#define EVENTSINK_H
#endif

#define _WIN32_DCOM
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "onecore.lib")

#ifndef _CreationEvent_h__
class EventSink : public IWbemObjectSink
{
    LONG m_lRef;
    bool bDone;

public:
    EventSink() { m_lRef = 0; }
    ~EventSink() { bDone = true; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT
        STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv);

    virtual HRESULT STDMETHODCALLTYPE Indicate(
        LONG lObjectCount,
        IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray
    );

    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        /* [in] */ LONG lFlags,
        /* [in] */ HRESULT hResult,
        /* [in] */ BSTR strParam,
        /* [in] */ IWbemClassObject __RPC_FAR* pObjParam
    );
};

class wmiEventRegistrant
{
    IWbemServices* pSvc = NULL;
    IWbemObjectSink* pStubSink = NULL;
    IWbemLocator* pLoc = NULL;
    IUnsecuredApartment* pUnsecApp = NULL;
    IUnknown* pStubUnk = NULL;
    EventSink* pSink = NULL;

public:
    wmiEventRegistrant();
    ~wmiEventRegistrant();

    bool registerForProcessCreatedEvents();
    
};
#endif    