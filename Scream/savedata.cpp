#pragma warning (disable : 4127)

#include "scream.h"
#include "savedata.h"

//=============================================================================
// Defines
//=============================================================================
#define PCM_PAYLOAD_SIZE    1152                        // PCM payload size (divisible by 2, 3 and 4 bytes per sample * 2 channels)
#define HEADER_SIZE         5                           // m_bSamplingFreqMarker, m_bBitsPerSampleMarker, m_bChannels, m_wChannelMask
#define CHUNK_SIZE          (PCM_PAYLOAD_SIZE + HEADER_SIZE)      // Add two bytes so we can send a small header with bytes/sample and sampling freq markers
#define MAX_CHUNK_SIZE      (PCM_PAYLOAD_SIZE + HEADER_SIZE)
#define NUM_CHUNKS          800                         // How many payloads in ring buffer
#define BUFFER_SIZE         CHUNK_SIZE * NUM_CHUNKS     // Ring buffer size

//=============================================================================
// Statics
//=============================================================================

// Client-level callback table
const WSK_CLIENT_DISPATCH WskSampleClientDispatch = {
    MAKE_WSK_VERSION(1, 0), // This sample uses WSK version 1.0
    0, // Reserved
    NULL // WskClientEvent callback is not required in WSK version 1.0
};

//=============================================================================
// Helper Functions
//=============================================================================
// IRP completion routine used for synchronously waiting for completion
NTSTATUS WskSampleSyncIrpCompletionRoutine(__in PDEVICE_OBJECT Reserved, __in PIRP Irp, __in PVOID Context) {    
    PKEVENT compEvent = (PKEVENT)Context;
    
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(Irp);
    
    KeSetEvent(compEvent, 2, FALSE);    

    return STATUS_MORE_PROCESSING_REQUIRED;
}

#pragma code_seg("PAGE")
//=============================================================================
// CSaveData
//=============================================================================

//=============================================================================
CSaveData::CSaveData() : m_bNumEndPoints(2), m_pBuffer(NULL), m_ulOffset(0), m_ulSendOffset(0), m_fWriteDisabled(FALSE), m_socket(NULL) {
    PAGED_CODE();

    DPF_ENTER(("[CSaveData::CSaveData]"));
    
    if (!g_UseIVSHMEM) {
        WSK_CLIENT_NPI   wskClientNpi;

        // allocate work item for this stream
        m_pWorkItem = (PSAVEWORKER_PARAM)ExAllocatePoolWithTag(NonPagedPool, sizeof(SAVEWORKER_PARAM), MSVAD_POOLTAG);
        if (m_pWorkItem) {
            m_pWorkItem->WorkItem = IoAllocateWorkItem(GetDeviceObject());
            KeInitializeEvent(&(m_pWorkItem->EventDone), NotificationEvent, TRUE);
        }

        // get us an IRP
        m_irp = IoAllocateIrp(1, FALSE);

        // initialize io completion sychronization event
        KeInitializeEvent(&m_syncEvent, SynchronizationEvent, FALSE);

        // Register with WSK.
        wskClientNpi.ClientContext = NULL;
        wskClientNpi.Dispatch = &WskSampleClientDispatch;
        WskRegister(&wskClientNpi, &m_wskSampleRegistration);
    }
} // CSaveData

//=============================================================================
CSaveData::~CSaveData() {
    PAGED_CODE();

    DPF_ENTER(("[CSaveData::~CSaveData]"));

    if (!g_UseIVSHMEM) {
        // frees the work item
        if (m_pWorkItem->WorkItem != NULL) {
            IoFreeWorkItem(m_pWorkItem->WorkItem);
            m_pWorkItem->WorkItem = NULL;
        }

        // close socket
        if (m_socket) {
            IoReuseIrp(m_irp, STATUS_UNSUCCESSFUL);
            IoSetCompletionRoutine(m_irp, WskSampleSyncIrpCompletionRoutine, &m_syncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)m_socket->Dispatch)->WskCloseSocket(m_socket, m_irp);
            KeWaitForSingleObject(&m_syncEvent, Executive, KernelMode, FALSE, NULL);
        }

        // Deregister with WSK. This call will wait until all the references to
        // the WSK provider NPI are released and all the sockets are closed. Note
        // that if the worker thread has not started yet, then when it eventually
        // starts, its WskCaptureProviderNPI call will fail and the work queue
        // will be flushed and cleaned up properly.
        WskDeregister(&m_wskSampleRegistration);

        // free irp
        IoFreeIrp(m_irp);

        if (m_pBuffer) {
            ExFreePoolWithTag(m_pBuffer, MSVAD_POOLTAG);
            IoFreeMdl(m_pMdl);
        }

        // delete endpoint objects
        BYTE i;
        for (i = 0; i < m_bNumEndPoints; i++)
            if (m_pEndPoints[i])
                delete m_pEndPoints[i];
    }
} // CSaveData

//=============================================================================
void CSaveData::DestroyWorkItems(void) {
    PAGED_CODE();
    
    DPF_ENTER(("[CSaveData::DestroyWorkItems]"));

    if (m_pWorkItem) {
        ExFreePoolWithTag(m_pWorkItem, MSVAD_POOLTAG);
        m_pWorkItem = NULL;
    }

} // DestroyWorkItems

//=============================================================================
void CSaveData::Disable(BOOL fDisable) {
    PAGED_CODE();

    m_fWriteDisabled = fDisable;
} // Disable

//=============================================================================
NTSTATUS CSaveData::SetDeviceObject(IN PDEVICE_OBJECT DeviceObject) {
    PAGED_CODE();

    ASSERT(DeviceObject);

    NTSTATUS ntStatus = STATUS_SUCCESS;
    
    m_pDeviceObject = DeviceObject;
    return ntStatus;
}

//=============================================================================
PDEVICE_OBJECT CSaveData::GetDeviceObject(void) {
    PAGED_CODE();

    return m_pDeviceObject;
}

#pragma code_seg("PAGE")
//=============================================================================
NTSTATUS CSaveData::Initialize(DWORD nSamplesPerSec, WORD wBitsPerSample, WORD nChannels, DWORD dwChannelMask) {
    PAGED_CODE();

    NTSTATUS          ntStatus = STATUS_SUCCESS;

    DPF_ENTER(("[CSaveData::Initialize]"));
    
    // Only multiples of 44100 and 48000 are supported
    m_bSamplingFreqMarker  = (BYTE)((nSamplesPerSec % 44100) ? (0 + (nSamplesPerSec / 48000)) : (128 + (nSamplesPerSec / 44100)));
    m_bBitsPerSampleMarker = (BYTE)(wBitsPerSample);
    m_bChannels = (BYTE)nChannels;
    m_wChannelMask = (WORD)dwChannelMask;
    m_usBytesPerMultichannelSample = (USHORT)(wBitsPerSample / 8 * nChannels);
    ASSERT(m_usBytesPerMultichannelSample <= MAX_CHANNELS_PCM * MAX_BITS_PER_SAMPLE_PCM / 8);

    // Allocate memory for data buffer.
    if (NT_SUCCESS(ntStatus)) {
        m_pBuffer = (PBYTE) ExAllocatePoolWithTag(NonPagedPool, BUFFER_SIZE, MSVAD_POOLTAG);
        if (!m_pBuffer) {
            DPF(D_TERSE, ("[Could not allocate memory for sending data]"));
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    // Allocate MDL for the data buffer
    if (NT_SUCCESS(ntStatus)) {
        m_pMdl = IoAllocateMdl(m_pBuffer, BUFFER_SIZE, FALSE, FALSE, NULL);
        if (m_pMdl == NULL) {
            DPF(D_TERSE, ("[Failed to allocate MDL]"));
            ntStatus = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            MmBuildMdlForNonPagedPool(m_pMdl);
        }
    }

    PCHAR ips[] = {
        "192.168.91.2",
        "192.168.91.1",
        "192.168.91.1",
        "192.168.91.1",
        "192.168.91.1",
        "192.168.91.1"
    };
    WORD masks[] = { 0x1, 0x2, 0x4, 0x8, 0x200, 0x400 };

    BYTE i;
    for (i = 0; i < m_bNumEndPoints; i++)
    {
        m_pEndPoints[i] = new (NonPagedPool, MSVAD_POOLTAG) EndPoint(
            ips[i],
            4010,
            m_pBuffer,
            i * (BUFFER_SIZE / m_bNumEndPoints),
            (i + 1) * (BUFFER_SIZE / m_bNumEndPoints),
            m_bBitsPerSampleMarker,
            m_bSamplingFreqMarker,
            masks[i],
            m_wChannelMask
            );
    }

    return ntStatus;
} // Initialize

//=============================================================================
IO_WORKITEM_ROUTINE SendDataWorkerCallback;

VOID SendDataWorkerCallback(PDEVICE_OBJECT pDeviceObject, IN  PVOID  Context) {
    UNREFERENCED_PARAMETER(pDeviceObject);

    PAGED_CODE();

    ASSERT(Context);

    PSAVEWORKER_PARAM pParam = (PSAVEWORKER_PARAM) Context;
    PCSaveData        pSaveData;

    ASSERT(pParam->pSaveData);

    if (pParam->WorkItem) {
        pSaveData = pParam->pSaveData;
        pSaveData->SendData();
    }

    KeSetEvent(&(pParam->EventDone), 0, FALSE);
} // SendDataWorkerCallback

#pragma code_seg()
//=============================================================================
void CSaveData::CreateSocket(void) {
    NTSTATUS            status;
    WSK_PROVIDER_NPI    pronpi;
    LPCTSTR             terminator;
    SOCKADDR_IN         locaddr4 = { AF_INET, RtlUshortByteSwap((USHORT)g_UnicastPort), 0, 0 };
    SOCKADDR_IN         sockaddr = { AF_INET, RtlUshortByteSwap((USHORT)g_UnicastPort), 0, 0 };
    
    DPF_ENTER(("[CSaveData::CreateSocket]"));
    
    // capture WSK provider
    status = WskCaptureProviderNPI(&m_wskSampleRegistration, WSK_INFINITE_WAIT, &pronpi);
    if(!NT_SUCCESS(status)){
        DPF(D_TERSE, ("Failed to capture provider NPI: 0x%X\n", status));
        return;
    }

    RtlIpv4StringToAddress(g_UnicastIPv4, true, &terminator, &(sockaddr.sin_addr));
    RtlCopyMemory(&m_sServerAddr, &sockaddr, sizeof(SOCKADDR_IN));
    
    // create socket
    IoReuseIrp(m_irp, STATUS_UNSUCCESSFUL);
    IoSetCompletionRoutine(m_irp, WskSampleSyncIrpCompletionRoutine, &m_syncEvent, TRUE, TRUE, TRUE);    
    pronpi.Dispatch->WskSocket(
        pronpi.Client,
        m_sServerAddr.ss_family,
        SOCK_DGRAM,
        IPPROTO_UDP,
        WSK_FLAG_DATAGRAM_SOCKET,
        NULL, // socket context
        NULL, // dispatch
        NULL, // Process
        NULL, // Thread
        NULL, // SecurityDescriptor
        m_irp);
    KeWaitForSingleObject(&m_syncEvent, Executive, KernelMode, FALSE, NULL);
    
    DPF(D_TERSE, ("WskSocket: %x", m_irp->IoStatus.Status));
    
    if (!NT_SUCCESS(m_irp->IoStatus.Status)) {
        DPF(D_TERSE, ("Failed to create socket: %x", m_irp->IoStatus.Status));
        
        if(m_socket) {
            IoReuseIrp(m_irp, STATUS_UNSUCCESSFUL);
            IoSetCompletionRoutine(m_irp, WskSampleSyncIrpCompletionRoutine, &m_syncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)m_socket->Dispatch)->WskCloseSocket(m_socket, m_irp);
            KeWaitForSingleObject(&m_syncEvent, Executive, KernelMode, FALSE, NULL);
        }
        
        // release the provider again, as we are finished with it
        WskReleaseProviderNPI(&m_wskSampleRegistration);
        
        return;
    }
    
    // save the socket
    m_socket = (PWSK_SOCKET)m_irp->IoStatus.Information;
    
    // release the provider again, as we are finished with it
    WskReleaseProviderNPI(&m_wskSampleRegistration);

    // bind the socket
    IoReuseIrp(m_irp, STATUS_UNSUCCESSFUL);
    IoSetCompletionRoutine(m_irp, WskSampleSyncIrpCompletionRoutine, &m_syncEvent, TRUE, TRUE, TRUE);
    status = ((PWSK_PROVIDER_DATAGRAM_DISPATCH)(m_socket->Dispatch))->WskBind(m_socket, (PSOCKADDR)(&locaddr4), 0, m_irp);
    KeWaitForSingleObject(&m_syncEvent, Executive, KernelMode, FALSE, NULL);
    
    DPF(D_TERSE, ("WskBind: %x", m_irp->IoStatus.Status));
    
    if (!NT_SUCCESS(m_irp->IoStatus.Status)) {
        DPF(D_TERSE, ("Failed to bind socket: %x", m_irp->IoStatus.Status));
        if(m_socket) {
            IoReuseIrp(m_irp, STATUS_UNSUCCESSFUL);
            IoSetCompletionRoutine(m_irp, WskSampleSyncIrpCompletionRoutine, &m_syncEvent, TRUE, TRUE, TRUE);
            ((PWSK_PROVIDER_BASIC_DISPATCH)m_socket->Dispatch)->WskCloseSocket(m_socket, m_irp);
            KeWaitForSingleObject(&m_syncEvent, Executive, KernelMode, FALSE, NULL);
        }
        
        return;
    }
}

//=============================================================================
void CSaveData::SendData() {
    WSK_BUF wskbuf;
    BYTE i;
    BOOL notAllSent;

    //ULONG storeOffset;
    
    if (!m_socket) {
        CreateSocket();
    }
    
    if (m_socket) {
        while (1) {
            notAllSent = FALSE;
            for (i = 0; i < m_bNumEndPoints; i++)
            {
                notAllSent = notAllSent || m_pEndPoints[i]->hasSomethingToSend();
                if (m_pEndPoints[i]->hasSomethingToSend())
                {
                    wskbuf.Mdl = m_pMdl;
                    wskbuf.Length = m_pEndPoints[i]->getChunkSize();
                    wskbuf.Offset = m_pEndPoints[i]->getSendOffset();
                    IoReuseIrp(m_irp, STATUS_UNSUCCESSFUL);
                    IoSetCompletionRoutine(m_irp, WskSampleSyncIrpCompletionRoutine, &m_syncEvent, TRUE, TRUE, TRUE);
                    ((PWSK_PROVIDER_DATAGRAM_DISPATCH)(m_socket->Dispatch))->WskSendTo(m_socket, &wskbuf, 0, (PSOCKADDR)m_pEndPoints[i]->getSockAddr(), 0, NULL, m_irp);
                    KeWaitForSingleObject(&m_syncEvent, Executive, KernelMode, FALSE, NULL);
                    DPF(D_TERSE, ("WskSendToEndpoint%d: %x, offset %d", i, m_irp->IoStatus.Status, m_pEndPoints[i]->getSendOffset()));

                    m_pEndPoints[i]->setNextSendOffset();
                }
            }

            if (!notAllSent)
                break;
        }
    }
}

#pragma code_seg("PAGE")
//=============================================================================
void CSaveData::WaitAllWorkItems(void) {
    PAGED_CODE();

    DPF_ENTER(("[CSaveData::WaitAllWorkItems]"));

    DPF(D_VERBOSE, ("[Waiting for WorkItem]"));
    KeWaitForSingleObject(&(m_pWorkItem->EventDone), Executive, KernelMode, FALSE, NULL);
    
} // WaitAllWorkItems

#pragma code_seg()
//=============================================================================
void CSaveData::WriteData(IN PBYTE pBuffer, IN ULONG ulByteCount) {
    ASSERT(pBuffer);

    LARGE_INTEGER timeOut = { 0 };
    NTSTATUS ntStatus;
    
    if (m_fWriteDisabled) {
        return;
    }

    DPF_ENTER(("[CSaveData::WriteData ulByteCount=%lu]", ulByteCount));

    // Undersized (paranoia)
    if (0 == ulByteCount) {
        return;
    }

    // Oversized (paranoia)
    if (ulByteCount > (CHUNK_SIZE * NUM_CHUNKS / 2)) {
        return;
    }

    BYTE i;
    ULONG toWrite = ulByteCount;
    PBYTE pointer = pBuffer;
    static USHORT bytesRemaining = 0;
    if (bytesRemaining != 0)
    {
        RtlCopyMemory(&(m_MSBuffer[m_usBytesPerMultichannelSample - bytesRemaining]), pointer, bytesRemaining);
        for (i = 0; i < m_bNumEndPoints; i++)
            m_pEndPoints[i]->WriteSample(m_MSBuffer);
        toWrite -= bytesRemaining;
        pointer += bytesRemaining;
        bytesRemaining = 0;
    }
    
    while (toWrite > 0)
    {
        if (toWrite < m_usBytesPerMultichannelSample)
        {
            RtlCopyMemory(m_MSBuffer, pointer, toWrite);
            bytesRemaining = m_usBytesPerMultichannelSample - (USHORT)toWrite;
            toWrite -= toWrite;
            break;
        }
        else
        {
            for (i = 0; i < m_bNumEndPoints; i++)
                m_pEndPoints[i]->WriteSample(pointer);
            toWrite -= m_usBytesPerMultichannelSample;
            pointer += m_usBytesPerMultichannelSample;
        }
    }
    ASSERT(toWrite == 0);

    // If I/O worker was done, relaunch it
    ntStatus = KeWaitForSingleObject(&(m_pWorkItem->EventDone), Executive, KernelMode, FALSE, &timeOut);
    if (STATUS_SUCCESS == ntStatus) {
            m_pWorkItem->pSaveData = this;
            KeResetEvent(&(m_pWorkItem->EventDone));
            IoQueueWorkItem(m_pWorkItem->WorkItem, SendDataWorkerCallback, CriticalWorkQueue, (PVOID)m_pWorkItem);
    }
} // WriteData

#pragma code_seg()
EndPoint::EndPoint(
    PCHAR ipaddr,
    USHORT port,
    PBYTE pBuffer,
    ULONG ulBufferBeginOffset,
    ULONG ulBufferEndOffset,
    BYTE bBitsPerSampleMarker,
    BYTE bSamplingFreqMarker,
    WORD wConfigChannelMask,
    WORD wInputChannelMask) :
    m_pBuffer(pBuffer),
    m_ulBufferBeginOffset(ulBufferBeginOffset),
    m_ulBufferEndOffset(ulBufferEndOffset),
    m_bSamplingFreqMarker(bSamplingFreqMarker),
    m_bBitsPerSampleMarker(bBitsPerSampleMarker),
    m_ulOffset(ulBufferBeginOffset),
    m_ulSendOffset(ulBufferBeginOffset),
    m_bChannelSelectors()
{
    LPCTSTR         terminator;
    SOCKADDR_IN     endPointAddr = { AF_INET, RtlUshortByteSwap(port), 0, 0 };

    DPF_ENTER(("[EndPoint::EndPoint]"));

    RtlIpv4StringToAddress(ipaddr, true, &terminator, &(endPointAddr.sin_addr));
    RtlCopyMemory(&m_sDestination, &endPointAddr, sizeof(SOCKADDR_IN));

    m_bBytesPerSample = bBitsPerSampleMarker / 8;
    //Maybe the input stream doesn't have certain channels in our endpoint configuration.
    m_wChannelMask = wConfigChannelMask & wInputChannelMask;

    WORD n = m_wChannelMask;
    WORD m = wInputChannelMask;

    BYTE i = 0;
    m_bChannels = 0;
    while (n)
    {
        if ((n & 0x0001) != 0) //if this channel is selected by the endpoint
        {
            //set 'm_bChannels'th channel selector to be 'i'th channel in the input stream.
            m_bChannelSelectors[m_bChannels] = i;
            m_bChannels += 1;
        }
        i += m & 0x0001; //if the input stream has this channel, increase counter
        n >>= 1; //next channel
        m >>= 1; //next channel
    }

    if ((m_bBytesPerSample * m_bChannels) == 0)
        m_usChunkSize = 0; //the endpoint will be disabled anyway
    else
        m_usChunkSize = (MAX_CHUNK_SIZE - HEADER_SIZE) / (m_bBytesPerSample * m_bChannels) * 
            (m_bBytesPerSample * m_bChannels) + HEADER_SIZE;
}

void EndPoint::WriteSample(IN PBYTE pBuffer)
{
    if (m_usChunkSize > 0)
    {
        ULONG w = (m_ulOffset - m_ulBufferBeginOffset) % m_usChunkSize;
        if (w <= 0)
        { //start a new chunk
            if ((m_ulBufferEndOffset - m_ulOffset) < m_usChunkSize)
                m_ulOffset = m_ulBufferBeginOffset;
            m_pBuffer[m_ulOffset] = m_bSamplingFreqMarker;
            m_pBuffer[m_ulOffset + 1] = m_bBitsPerSampleMarker;
            m_pBuffer[m_ulOffset + 2] = m_bChannels;
            m_pBuffer[m_ulOffset + 3] = (BYTE)(m_wChannelMask & 0xFF);
            m_pBuffer[m_ulOffset + 4] = (BYTE)(m_wChannelMask >> 8 & 0xFF);
            DPF(D_TERSE, ("NewChunkAt %d", m_ulOffset));
            m_ulOffset += HEADER_SIZE;
        }

        //continue to fill the chunk    
        BYTE i;
        BYTE j;
        ULONG offset = m_ulOffset;
        for (i = 0; i < m_bChannels; i++)
        {
            /*RtlCopyMemory(
                &(m_pBuffer[m_ulOffset]),
                &(pBuffer[m_bChannelSelectors[i] * m_bBytesPerSample]),
                m_bBytesPerSample
            );*/
            for (j = 0; j < m_bBytesPerSample; j++)
            {
                m_pBuffer[offset] = pBuffer[m_bChannelSelectors[i] * m_bBytesPerSample + j];
                offset++;
            }
            //m_ulOffset += m_bBytesPerSample;
        }
        if (offset < m_ulBufferEndOffset)
            m_ulOffset = offset;
        else
            m_ulOffset = m_ulBufferBeginOffset;
    }
    ASSERT((m_ulOffset >= m_ulBufferBeginOffset) && (m_ulOffset < m_ulBufferEndOffset));
}

inline BOOL EndPoint::hasSomethingToSend()
{
    // Note: When storeOffset < sendOffset, we can always send a chunk.
    //BOOL res = !((m_ulOffset >= m_ulSendOffset) && ((m_ulOffset - m_ulSendOffset) < m_usChunkSize));
    //DPF(D_TERSE, ("%d %d %d", m_ulOffset, m_ulSendOffset, res));
    return !((m_ulOffset >= m_ulSendOffset) && ((m_ulOffset - m_ulSendOffset) < m_usChunkSize));
}

inline ULONG EndPoint::getSendOffset()
{
    return m_ulSendOffset;
}

inline USHORT EndPoint::getChunkSize()
{
    return m_usChunkSize;
}

inline SOCKADDR_STORAGE* EndPoint::getSockAddr()
{
    return &m_sDestination;
}

void EndPoint::setNextSendOffset()
{
    if (m_ulBufferEndOffset < m_ulSendOffset + 2*m_usChunkSize)
        m_ulSendOffset = m_ulBufferBeginOffset;
    else
        m_ulSendOffset += m_usChunkSize;
    ASSERT((m_ulSendOffset + m_usChunkSize <= m_ulBufferEndOffset) && (m_ulSendOffset >= m_ulBufferBeginOffset));
}
