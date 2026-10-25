#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include <rex/runtime.h>
#include <rex/kernel/xboxkrnl/error.h>
#include <rex/ppc/function.h>
#include <rex/hook.h>
#include <rex/string.h>
#include <rex/system/function_dispatcher.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xevent.h>
#include <rex/system/xio.h>
#include <rex/system/xsocket.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

#if REX_PLATFORM_WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#endif

namespace default_mp {

void InstallXamOverrides(rex::Runtime* runtime);

}  // namespace default_mp

namespace default_mp::detail {

using namespace rex;
using namespace rex::system;

constexpr uint32_t kAppXgi = 0xFB;
constexpr uint32_t kAppXLiveBase = 0xFC;

constexpr uint32_t kMsgXgiSessionCreate = 0x000B0010;
constexpr uint32_t kMsgXgiSessionDelete = 0x000B0011;
constexpr uint32_t kMsgXgiSessionJoinLocal = 0x000B0012;
constexpr uint32_t kMsgXgiSessionLeaveLocal = 0x000B0013;
constexpr uint32_t kMsgXLiveGetServiceInfo = 0x00058007;

constexpr uint32_t kImpXMsgStartIORequestEx = 0x827FB674;
constexpr uint32_t kImpXMsgStartIORequest = 0x827FB684;
constexpr uint32_t kImpXMsgInProcessCall = 0x827FB694;
constexpr uint32_t kImpXamUserCheckPrivilege = 0x827FB714;
constexpr uint32_t kImpXMsgCancelIORequest = 0x827FB844;
constexpr uint32_t kImpXamGetOverlappedResult = 0x827FB8C4;
constexpr uint32_t kImpXMsgCompleteIORequest = 0x827FB8D4;

constexpr uint32_t kImpXNetXnAddrToInAddr = 0x827FC354;
constexpr uint32_t kImpXNetInAddrToXnAddr = 0x827FC374;
constexpr uint32_t kImpXNetInAddrToString = 0x827FC384;
constexpr uint32_t kImpXNetXnAddrToMachineId = 0x827FC3A4;
constexpr uint32_t kImpXNetQosListen = 0x827FC3F4;
constexpr uint32_t kImpXNetQosServiceLookup = 0x827FC414;
constexpr uint32_t kImpXNetGetTitleXnAddr = 0x827FC434;
constexpr uint32_t kImpXNetGetEthernetLinkStatus = 0x827FC444;
constexpr uint32_t kImpNetRecvFrom = 0x827FC504;
constexpr uint32_t kImpNetSendTo = 0x827FC524;

constexpr uint32_t kWsaeWouldBlock = 0x2733;
constexpr uint32_t kWsaeNotSock = 0x2736;

struct XMSGSTARTIOREQUEST_UNKNOWNARG {
  be<uint32_t> unk_0;
  be<uint32_t> unk_1;
};

struct XNADDR {
  be<uint32_t> ina;
  be<uint32_t> ina_online;
  be<uint16_t> port_online;
  uint8_t ab_enet[6];
  uint8_t ab_online[20];
};

struct XNQOSINFO {
  uint8_t flags;
  uint8_t reserved;
  be<uint16_t> probes_xmit;
  be<uint16_t> probes_recv;
  be<uint16_t> data_len;
  be<uint32_t> data_ptr;
  be<uint16_t> rtt_min_in_msecs;
  be<uint16_t> rtt_med_in_msecs;
  be<uint32_t> up_bits_per_sec;
  be<uint32_t> down_bits_per_sec;
};

struct XNQOS {
  be<uint32_t> count;
  be<uint32_t> count_pending;
  XNQOSINFO info[1];
};

constexpr uint32_t kXNetGetXnAddrEthernet = 0x00000002;
constexpr uint32_t kXNetGetXnAddrStatic = 0x00000004;

constexpr uint32_t kXNetEthernetLinkActive = 0x01;
constexpr uint32_t kXNetEthernetLink100Mbps = 0x02;
constexpr uint32_t kXNetEthernetLinkFullDuplex = 0x08;

X_HRESULT DispatchSync(uint32_t app, uint32_t message, uint32_t buffer_ptr, uint32_t buffer_length) {
  return REX_KERNEL_STATE()->app_manager()->DispatchMessageSync(app, message, buffer_ptr, buffer_length);
}

X_HRESULT DispatchAsync(uint32_t app, uint32_t message, uint32_t buffer_ptr,
                        uint32_t buffer_length) {
  return REX_KERNEL_STATE()->app_manager()->DispatchMessageAsync(app, message, buffer_ptr, buffer_length);
}

bool HandleXgiMessage(uint32_t message, uint32_t buffer_ptr, uint32_t buffer_length,
                      X_HRESULT& out_result) {
  auto* memory = REX_KERNEL_MEMORY();
  auto* buffer = buffer_ptr ? memory->TranslateVirtual(buffer_ptr) : nullptr;

  switch (message) {
    case kMsgXgiSessionCreate: {
      if (buffer_length && buffer_length != 28) {
        out_result = X_E_INVALIDARG;
        return true;
      }
      if (!buffer) {
        out_result = X_E_SUCCESS;
        return true;
      }

      uint32_t session_info_ptr = memory::load_and_swap<uint32_t>(buffer + 0x14);
      uint32_t nonce_ptr = memory::load_and_swap<uint32_t>(buffer + 0x18);

      if (session_info_ptr) {
        auto* info = memory->TranslateVirtual(session_info_ptr);
        memory::store_and_swap<uint32_t>(info + 0x00, 0xAB1234CD);
        memory::store_and_swap<uint32_t>(info + 0x04, 0xEF5678AB);
        memory::store_and_swap<uint32_t>(info + 0x08, 0xC0A80164);
        memory::store_and_swap<uint32_t>(info + 0x0C, 0);
        memory::store_and_swap<uint16_t>(info + 0x10, 0);
        std::memset(info + 0x12, 0xCC, 6);
        std::memset(info + 0x18, 0, 20);
        std::memset(info + 0x2C, 0xAB, 16);
      }

      if (nonce_ptr) {
        auto* nonce = memory->TranslateVirtual(nonce_ptr);
        memory::store_and_swap<uint32_t>(nonce + 0, 0x12345678);
        memory::store_and_swap<uint32_t>(nonce + 4, 0x9ABCDEF0);
      }

      out_result = X_E_SUCCESS;
      return true;
    }
    case kMsgXgiSessionDelete:
    case kMsgXgiSessionJoinLocal:
    case kMsgXgiSessionLeaveLocal:
      out_result = X_E_SUCCESS;
      return true;
    default:
      return false;
  }
}

bool HandleXLiveBaseMessage(uint32_t message, uint32_t buffer_ptr, uint32_t buffer_length,
                            X_HRESULT& out_result) {
  if (message != kMsgXLiveGetServiceInfo) {
    return false;
  }

  // XOnlineGetServiceInfo(service_id, pServiceInfo). The SDK returns
  // ERROR_CONNECTION_INVALID unconditionally, which makes titles report
  // "no network connection" even in local/system-link modes. Report the
  // service as available and fill the buffer with a zeroed, valid record.
  auto* memory = REX_KERNEL_MEMORY();
  if (buffer_ptr && buffer_length > 0) {
    auto* buffer = memory->TranslateVirtual(buffer_ptr);
    std::memset(buffer, 0, buffer_length);
    // Service is "available": status at the head of the record.
    if (buffer_length >= 4) {
      memory::store_and_swap<uint32_t>(buffer, 1);
    }
  }

  out_result = X_E_SUCCESS;
  return true;
}

X_HRESULT DispatchWithOverrides(uint32_t app, uint32_t message, uint32_t buffer_ptr,
                                uint32_t buffer_length) {
  X_HRESULT result = X_ERROR_NOT_FOUND;
  if (app == kAppXgi && HandleXgiMessage(message, buffer_ptr, buffer_length, result)) {
    return result;
  }
  if (app == kAppXLiveBase && HandleXLiveBaseMessage(message, buffer_ptr, buffer_length, result)) {
    return result;
  }
  return DispatchSync(app, message, buffer_ptr, buffer_length);
}

X_HRESULT StartIoRequestWithOverrides(uint32_t app, uint32_t message, uint32_t overlapped_ptr,
                                      uint32_t buffer_ptr, uint32_t buffer_length) {
  X_HRESULT result = X_ERROR_NOT_FOUND;
  bool handled = false;
  if (app == kAppXgi) {
    handled = HandleXgiMessage(message, buffer_ptr, buffer_length, result);
  } else if (app == kAppXLiveBase) {
    handled = HandleXLiveBaseMessage(message, buffer_ptr, buffer_length, result);
  }

  if (!handled) {
    result = DispatchAsync(app, message, buffer_ptr, buffer_length);
    if (result == X_E_NOTFOUND) {
      XThread::SetLastError(X_ERROR_NOT_FOUND);
    }
  }

  if (overlapped_ptr) {
    REX_KERNEL_STATE()->CompleteOverlappedImmediate(overlapped_ptr, result);
    result = X_ERROR_IO_PENDING;
  }

  if (result == X_ERROR_SUCCESS || result == X_ERROR_IO_PENDING) {
    XThread::SetLastError(0);
  }
  return result;
}

u32 XamUserCheckPrivilegeOverride(u32 user_index, u32 mask, mapped_u32 out_value) {
  (void)mask;
  // 0xFF is the "any signed-in user" sentinel, so accept it alongside the four
  // real local slots. Every slot 0..3 must report the privilege as granted:
  // the game checks each splitscreen player's privileges before it will let
  // that controller join, so rejecting 1..3 with X_ERROR_NO_SUCH_USER silently
  // blocks players 2-4 even though their input is arriving fine.
  if (user_index != 0xFF && user_index >= 4) {
    return X_ERROR_INVALID_PARAMETER;
  }

  if (out_value) {
    *out_value = 1;
  }
  return X_ERROR_SUCCESS;
}

u32 XMsgInProcessCallOverride(u32 app, u32 message, u32 arg1, u32 arg2) {
  return DispatchWithOverrides(app, message, arg1, arg2);
}

u32 XMsgStartIORequestExOverride(u32 app, u32 message, ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr,
                                 u32 buffer_ptr, u32 buffer_length,
                                 ppc_ptr_t<XMSGSTARTIOREQUEST_UNKNOWNARG> unknown_ptr) {
  (void)unknown_ptr;
  return StartIoRequestWithOverrides(app, message, overlapped_ptr.guest_address(), buffer_ptr,
                                     buffer_length);
}

u32 XMsgStartIORequestOverride(u32 app, u32 message, ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr,
                               u32 buffer_ptr, u32 buffer_length) {
  return StartIoRequestWithOverrides(app, message, overlapped_ptr.guest_address(), buffer_ptr,
                                     buffer_length);
}

u32 XMsgCancelIORequestOverride(ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr, u32 wait) {
  X_HANDLE event_handle = XOverlappedGetEvent(overlapped_ptr);
  if (event_handle && wait) {
    auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
    if (ev) {
      ev->Wait(0, 0, true, nullptr);
    }
  }
  return 0;
}

u32 XMsgCompleteIORequestOverride(ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr, u32 result,
                                  u32 extended_error, u32 length) {
  REX_KERNEL_STATE()->CompleteOverlappedImmediateEx(overlapped_ptr.guest_address(), result,
                                                    extended_error, length);
  return X_ERROR_SUCCESS;
}

u32 XamGetOverlappedResultOverride(ppc_ptr_t<XAM_OVERLAPPED> overlapped_ptr, mapped_u32 length_ptr,
                                   u32 unknown) {
  (void)unknown;
  uint32_t result = 0;
  if (overlapped_ptr->result != X_ERROR_IO_PENDING) {
    result = overlapped_ptr->result;
  } else if (!overlapped_ptr->event) {
    result = X_ERROR_IO_INCOMPLETE;
  } else {
    auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(overlapped_ptr->event);
    result = ev->Wait(3, 1, 0, nullptr);
    if (XSUCCEEDED(result)) {
      result = overlapped_ptr->result;
    } else {
      result = kernel::xboxkrnl::xeRtlNtStatusToDosError(result);
    }
  }
  if (XSUCCEEDED(result) && length_ptr) {
    *length_ptr = overlapped_ptr->length;
  }
  return result;
}

u32 NetDllXNetGetTitleXnAddrOverride(u32 caller, ppc_ptr_t<XNADDR> addr_ptr) {
  (void)caller;
  addr_ptr->ina = 0xC0A80164;
  addr_ptr->ina_online = 0;
  addr_ptr->port_online = 0;
  std::memset(addr_ptr->ab_enet, 0xCC, sizeof(addr_ptr->ab_enet));
  std::memset(addr_ptr->ab_online, 0, sizeof(addr_ptr->ab_online));
  return kXNetGetXnAddrEthernet | kXNetGetXnAddrStatic;
}

u32 NetDllXNetXnAddrToMachineIdOverride(u32 caller, ppc_ptr_t<XNADDR> addr_ptr,
                                        mapped_u32 id_ptr) {
  (void)caller;
  (void)addr_ptr;
  if (id_ptr) {
    *id_ptr = 1;
  }
  return 0;
}

void NetDllXNetInAddrToStringOverride(u32 caller, u32 in_addr_val, mapped_string string_out,
                                      u32 string_size) {
  (void)caller;
  (void)in_addr_val;
  if (string_out) {
    rex::string::copy_truncating(string_out.host_address(), "127.0.0.1", string_size);
  }
}

u32 NetDllXNetXnAddrToInAddrOverride(u32 caller, ppc_ptr_t<XNADDR> xn_addr, mapped_void xid,
                                     mapped_void in_addr) {
  (void)caller;
  (void)xid;
  if (in_addr && xn_addr) {
    auto* out = REX_KERNEL_MEMORY()->TranslateVirtual(in_addr.guest_address());
    memory::store<uint32_t>(out, xn_addr->ina);
  }
  return 0;
}

u32 NetDllXNetInAddrToXnAddrOverride(u32 caller, mapped_void in_addr, ppc_ptr_t<XNADDR> xn_addr,
                                     mapped_void xid) {
  (void)caller;
  (void)xid;
  if (xn_addr && in_addr) {
    auto* src = REX_KERNEL_MEMORY()->TranslateVirtual(in_addr.guest_address());
    xn_addr->ina = memory::load<uint32_t>(src);
    xn_addr->ina_online = 0;
    xn_addr->port_online = 0;
    std::memset(xn_addr->ab_enet, 0xCC, sizeof(xn_addr->ab_enet));
    std::memset(xn_addr->ab_online, 0, sizeof(xn_addr->ab_online));
  }
  return 0;
}

u32 NetDllXNetQosServiceLookupOverride(u32 caller, u32 flags, u32 event_handle,
                                       mapped_u32 pqos) {
  (void)caller;
  (void)flags;
  if (pqos) {
    uint32_t qos_guest = REX_KERNEL_MEMORY()->SystemHeapAlloc(sizeof(XNQOS));
    auto* qos = REX_KERNEL_MEMORY()->TranslateVirtual<XNQOS*>(qos_guest);
    qos->count = 1;
    qos->count_pending = 0;
    std::memset(&qos->info[0], 0, sizeof(qos->info[0]));
    *pqos = qos_guest;
  }
  if (event_handle) {
    auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
    if (ev) {
      ev->Set(0, false);
    }
  }
  return 0;
}

u32 NetDllXNetQosListenOverride(u32 caller, mapped_void id, mapped_void data, u32 data_size,
                                u32 r7, u32 flags) {
  (void)caller;
  (void)id;
  (void)data;
  (void)data_size;
  (void)r7;
  (void)flags;
  return 0;
}

u32 NetDllXNetGetEthernetLinkStatusOverride(u32 caller) {
  (void)caller;
  return kXNetEthernetLinkActive | kXNetEthernetLink100Mbps | kXNetEthernetLinkFullDuplex;
}

u32 NetDllRecvFromOverride(u32 caller, u32 socket_handle, mapped_void buf_ptr, u32 buf_len,
                           u32 flags, ppc_ptr_t<XSOCKADDR_IN> from_ptr, mapped_u32 fromlen_ptr) {
  (void)caller;
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    XThread::SetLastError(kWsaeNotSock);
    return static_cast<uint32_t>(-1);
  }

  N_XSOCKADDR_IN native_from;
  if (from_ptr) {
    native_from = *from_ptr;
  }
  uint32_t native_fromlen = fromlen_ptr ? fromlen_ptr.value() : 0;
  int ret = socket->RecvFrom(buf_ptr, buf_len, flags, &native_from, fromlen_ptr ? &native_fromlen : nullptr);

  if (from_ptr) {
    from_ptr->sin_family = native_from.sin_family;
    from_ptr->sin_port = native_from.sin_port;
    from_ptr->sin_addr = native_from.sin_addr;
    std::memset(from_ptr->x_sin_zero, 0, sizeof(from_ptr->x_sin_zero));
  }
  if (fromlen_ptr) {
    *fromlen_ptr = native_fromlen;
  }

  if (ret == -1) {
    // The socket object has already recorded the cause; surface it as a would
    // block so callers retry (WSA errors are not available here).
    XThread::SetLastError(kWsaeWouldBlock);
    return static_cast<uint32_t>(-1);
  }

  XThread::SetLastError(0);
  return static_cast<uint32_t>(ret);
}

u32 NetDllSendToOverride(u32 caller, u32 socket_handle, mapped_void buf_ptr, u32 buf_len,
                         u32 flags, ppc_ptr_t<XSOCKADDR_IN> to_ptr, u32 to_len) {
  (void)caller;
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    XThread::SetLastError(kWsaeNotSock);
    return static_cast<uint32_t>(-1);
  }

  N_XSOCKADDR_IN native_to(to_ptr);
  int ret = socket->SendTo(buf_ptr, buf_len, flags, &native_to, to_len);
  if (ret == -1) {
    XThread::SetLastError(kWsaeWouldBlock);
    return static_cast<uint32_t>(-1);
  }

  XThread::SetLastError(0);
  return static_cast<uint32_t>(ret);
}

}  // namespace default_mp::detail

// These hooks replace the SDK's default XAM/net exports with offline-friendly
// behaviour. They must live in the default_mp translation unit that declares
// the generated imports; the kernel exports are registered by name, so a hook
// defined here takes precedence over the SDK's weak implementations.
// A guest export override needs both halves:
//  - REX_HOOK: patches direct `__imp__` calls resolved at link time.
//  - REX_EXPORT: registers in the PPCFuncRegistrar so XexGetProcedureAddress
//    (which the game uses for several Xam calls) resolves to our version.
#define DEFAULT_MP_HOOK(symbol, fn)              \
  REX_EXTERN(__imp__##symbol);                   \
  REX_EXPORT(__imp__##symbol, default_mp::detail::fn)

// XAM message apps (XGI / XLiveBase).
DEFAULT_MP_HOOK(XMsgInProcessCall, XMsgInProcessCallOverride)
DEFAULT_MP_HOOK(XMsgStartIORequest, XMsgStartIORequestOverride)
DEFAULT_MP_HOOK(XMsgStartIORequestEx, XMsgStartIORequestExOverride)
DEFAULT_MP_HOOK(XMsgCancelIORequest, XMsgCancelIORequestOverride)
DEFAULT_MP_HOOK(XMsgCompleteIORequest, XMsgCompleteIORequestOverride)
DEFAULT_MP_HOOK(XamGetOverlappedResult, XamGetOverlappedResultOverride)
DEFAULT_MP_HOOK(XamUserCheckPrivilege, XamUserCheckPrivilegeOverride)

// System-link / LAN network state.
DEFAULT_MP_HOOK(NetDll_XNetGetTitleXnAddr, NetDllXNetGetTitleXnAddrOverride)
DEFAULT_MP_HOOK(NetDll_XNetXnAddrToMachineId, NetDllXNetXnAddrToMachineIdOverride)
DEFAULT_MP_HOOK(NetDll_XNetInAddrToString, NetDllXNetInAddrToStringOverride)
DEFAULT_MP_HOOK(NetDll_XNetXnAddrToInAddr, NetDllXNetXnAddrToInAddrOverride)
DEFAULT_MP_HOOK(NetDll_XNetInAddrToXnAddr, NetDllXNetInAddrToXnAddrOverride)
DEFAULT_MP_HOOK(NetDll_XNetQosServiceLookup, NetDllXNetQosServiceLookupOverride)
DEFAULT_MP_HOOK(NetDll_XNetQosListen, NetDllXNetQosListenOverride)
DEFAULT_MP_HOOK(NetDll_XNetGetEthernetLinkStatus, NetDllXNetGetEthernetLinkStatusOverride)

#undef DEFAULT_MP_HOOK

// Keep this at the end of the file so it is never the active translation unit
// for the generated imports above.
void default_mp::InstallXamOverrides(rex::Runtime* runtime) { (void)runtime; }

