#ifndef _MSVAD_SAVEDATA_H
#define _MSVAD_SAVEDATA_H

#pragma warning(push)
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

// fix strange warnings from wsk.h
#pragma warning(disable:4510)
#pragma warning(disable:4512)
#pragma warning(disable:4610)

#include <ntddk.h>
#include <wsk.h>

#pragma warning(pop)

//-----------------------------------------------------------------------------
//  Forward declaration
//-----------------------------------------------------------------------------
class CSaveData;
typedef CSaveData *PCSaveData;

//-----------------------------------------------------------------------------
//  Structs
//-----------------------------------------------------------------------------

// Parameter to workitem.
#include <pshpack1.h>
typedef struct _SAVEWORKER_PARAM {
    PIO_WORKITEM     WorkItem;
    PCSaveData       pSaveData;
    KEVENT           EventDone;
} SAVEWORKER_PARAM;
typedef SAVEWORKER_PARAM *PSAVEWORKER_PARAM;
#include <poppack.h>

//-----------------------------------------------------------------------------
//  Classes
//-----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// EndPoint
//   Store information for multiple packet destinations.
//
class EndPoint {
protected:
    WORD                m_wChannelMask;
    BYTE                m_bChannels;
    const BYTE          m_bSamplingFreqMarker;
    const BYTE          m_bBitsPerSampleMarker;
    BYTE                m_bBytesPerSample;
    BYTE                m_bChannelSelectors[MAX_CHANNELS_PCM];

    SOCKADDR_STORAGE    m_sDestination;

    const PBYTE         m_pBuffer;
    const ULONG         m_ulBufferBeginOffset; //inclusive
    const ULONG         m_ulBufferEndOffset; //exclusive
    ULONG               m_ulOffset;
    ULONG               m_ulSendOffset;

    USHORT              m_usChunkSize;
public:
    EndPoint(PCHAR ipaddr,
        USHORT port,
        PBYTE pBuffer, 
        ULONG ulBufferBeginOffset, 
        ULONG ulBufferEndOffset, 
        BYTE bBitsPerSampleMarker,
        BYTE bSamplingFreqMarker,
        WORD wConfigChannelMask,
        WORD wInputChannelMask
        );
    //~EndPoint();

    void                        WriteSample(IN PBYTE pBuffer);
    inline BOOL                 hasSomethingToSend();
    inline ULONG                getSendOffset();
    inline USHORT               getChunkSize();
    inline SOCKADDR_STORAGE*    getSockAddr();

    void                setNextSendOffset();
};
typedef EndPoint* PEndPoint;

///////////////////////////////////////////////////////////////////////////////
// CSaveData
//   Saves the wave data to disk.
//
IO_WORKITEM_ROUTINE SendDataWorkerCallback;

class CSaveData {
protected:
    WSK_REGISTRATION            m_wskSampleRegistration;
    PWSK_SOCKET                 m_socket;
    PIRP                        m_irp;
    KEVENT                      m_syncEvent;
    
    PBYTE                       m_pBuffer;
    ULONG                       m_ulOffset;
    ULONG                       m_ulSendOffset;
    PMDL                        m_pMdl;
    
    static PDEVICE_OBJECT       m_pDeviceObject;
    static PSAVEWORKER_PARAM    m_pWorkItem;

    BOOL                        m_fWriteDisabled;
    
    SOCKADDR_STORAGE            m_sServerAddr;

    BYTE                        m_bSamplingFreqMarker;
    BYTE                        m_bBitsPerSampleMarker;
    USHORT                      m_usBytesPerMultichannelSample;
    BYTE                        m_bChannels;
    WORD                        m_wChannelMask;

    const BYTE                  m_bNumEndPoints;
    PEndPoint                   m_pEndPoints[MAX_ENDPOINTS];
    BYTE                        m_MSBuffer[MAX_CHANNELS_PCM * MAX_BITS_PER_SAMPLE_PCM / 8]; //temperory buffer for single multi-channel sample

public:
    CSaveData();
    ~CSaveData();

    NTSTATUS                    Initialize(DWORD nSamplesPerSec, WORD wBitsPerSample, WORD nChannels, DWORD dwChannelMask);
    void                        Disable(BOOL fDisable);
    
    static void                 DestroyWorkItems(void);
    void                        WaitAllWorkItems(void);
    
    static NTSTATUS             SetDeviceObject(IN PDEVICE_OBJECT DeviceObject);
    static PDEVICE_OBJECT       GetDeviceObject(void);
    
    void                        WriteData(IN PBYTE pBuffer, IN ULONG ulByteCount);

private:
    static NTSTATUS             InitializeWorkItem(IN PDEVICE_OBJECT DeviceObject);

    void                        CreateSocket(void);
    void                        SendData();
    friend VOID                 SendDataWorkerCallback(PDEVICE_OBJECT pDeviceObject, IN PVOID Context);
};
typedef CSaveData *PCSaveData;

#endif
