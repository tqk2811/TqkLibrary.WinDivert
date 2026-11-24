# Backlog

Việc còn treo và việc nên làm của thư viện. Xử lý xong mục nào thì xoá mục đó trong cùng commit với bản sửa.

Phần lớn mục chuyển từ backlog của app ProxyDivert ngày 2026-11-08. Mục mang mã A/B/E đến từ đợt rà soát ngày 2026-09-08: A = lỗi phát hiện từ phía app, B = lỗi WinDivert, E = thiết kế (OOP, tái sử dụng, test). Mức `Cao`/`Vừa`/`Thấp` theo nhãn trong tiêu đề; mục E: `Must` = đã gây lỗi thật hoặc chặn việc mở rộng, `Should` = giảm trùng lặp hoặc cho phép test, `Nice` = sạch hơn, không đổi hành vi. Đường dẫn `src/ProxyDivert.*` là của repo app ProxyDivert (repo cha, nhúng thư viện này làm submodule); đường dẫn khác tính từ gốc repo này.

### Pump NETWORK: nhận gói theo lô (RecvEx/SendEx)

- **Vấn đề:** pump nhận và gửi từng gói một. Batch giảm số syscall nhưng làm gói đầu lô chờ cả lô, tăng trễ từng gói; vì vậy chưa làm.
- **Hướng làm:** chỉ làm nếu sau khi thu hẹp filter (2026-10-08) đo vẫn thấy pump bão hoà CPU; giới hạn lô ≤ 8, flush ngay sau mỗi lần recv. Binding `RecvEx` đã có, thiếu `SendEx`. Đo ngày 2026-10-09 (Release, 32 thread đốt CPU khi đang chơi game): gói chờ tối đa < 0,4ms, mỗi lần recv gần như chỉ có 1 gói, nên chưa cần. Nhận cả lô rồi đẩy sang thread khác xử lý còn tệ hơn: thêm một lần đánh thức thread, và nhiều worker thì đảo thứ tự gói cùng flow.
- **Vị trí:** `src/TqkLibrary.WinDivert/Pipeline/PacketPump.cs`, `Native/WinDivertNative.cs`.
- **Ngày ghi:** 2026-10-08.

### SYN chưa theo dõi của process không liên quan vẫn chờ một lượt quét bảng kernel

- **Vấn đề:** mọi SYN chưa theo dõi của cả máy (kể cả app không bị chuyển hướng) bị giữ tới khi quét bảng kernel xong, trễ thiết lập connection vài ms. Pump không còn bị chặn, nhưng connection của app khác vẫn chậm chút.
- **Hướng làm:** bỏ qua quét khi tracker không có pid target nào; hoặc cache port nguồn đã biết không thuộc target; hoặc chờ SOCKET event vài ms trước khi quét. Đo trễ SYN của app không target trước/sau.
- **Vị trí:** `src/TqkLibrary.WinDivert.Redirect/NatRedirectMiddleware.cs` (`HoldSynForReconcile`), `Flow/CoalescedSweep.cs`.
- **Ngày ghi:** 2026-10-08.

### Test filter chưa kiểm được cú pháp với driver

- **Vấn đề:** `RedirectFilterTests` chỉ so chuỗi, không chứng minh WinDivert chấp nhận filter.
- **Hướng làm:** thêm binding `WinDivertHelperCompileFilter` (không cần admin) và test biên dịch từng tổ hợp.
- **Vị trí:** `src/TqkLibrary.WinDivert.Tests/RedirectFilterTests.cs`.
- **Ngày ghi:** 2026-10-08.

### Test RelayTeardownTests chập chờn khi máy bận

- **Vấn đề:** `DisposingTheRelayResetsAConnectionItHasAccepted` rớt một lần (15s) khi chạy cả bộ lúc máy bận, chạy lại thì xanh.
- **Vị trí:** `src/TqkLibrary.WinDivert.Tests/RelayTeardownTests.cs:64`.
- **Ngày ghi:** 2026-10-08.

### Lối tắt pump là bản chép tay quyết định của NAT

- **Vấn đề:** `UntrackedEgressBypass` lặp lại điều kiện của `NatRedirectMiddleware` (mask giao thức, cổng relay, FlowKey, kiểm lại). NAT đổi mà quên sửa bypass thì gói bị thả sai; thêm middleware built-in mới vào `AddTrailingMiddlewares` cũng không tự tắt bypass. Nên chuyển quyết định vào NAT (vd `CanPassUntouched`) hoặc thêm test chạy pipeline thật để kiểm hai bên khớp nhau; thiếu cả test cổng relay = 0 và bypass ném exception.
- **Vị trí:** `src/TqkLibrary.WinDivert.Redirect/UntrackedEgressBypass.cs`, `ProcessRedirector.cs` (`CreateBypass`).
- **Ngày ghi:** 2026-10-08 (finding review đợt fast path).

### Một nửa cặp pump chết thì cả đường chuyển hướng hỏng mà không ai dừng engine

- **Vấn đề:** sau khi tách handle chiều đi / chiều về, nếu riêng pump `*-reply` dừng bất thường (hoặc một trong hai pump chiều đi `*-tcp` / `*-udp` sau đợt tách theo giao thức, khi đó cả giao thức đó mất chuyển hướng) thì chiều đi vẫn đổi SYN sang relay nhưng không ai đổi gói trả về, mọi kết nối được chuyển hướng treo; log chỉ nói "traffic on this handle is no longer redirected". ProxyDivert.Core cũng không xử lý `PumpStopped`. Nên dừng/báo cả redirector khi một nửa cặp chết. Kèm ràng buộc ngầm: pipeline chiều về chỉ có NAT, stage mới muốn thấy gói trả về sẽ không thấy.
- **Vị trí:** `src/TqkLibrary.WinDivert.Redirect/ProcessRedirector.cs` (`OnPumpStopped`, `StartRelayReplyPump`).
- **Ngày ghi:** 2026-10-08 (finding review đợt tách handle).

### Mảnh IPv4 thứ hai trở đi bị NAT ghi đè "port"

- **Vấn đề:** parser và NAT không kiểm fragment. Từ mảnh thứ hai trở đi của gói IPv4 bị phân mảnh không có header TCP/UDP, nên hai byte mà code coi là port thực ra là payload; `WritePort` vẫn ghi đè lên đó và làm hỏng gói. TCP hầu như không bị phân mảnh, nhưng UDP lớn (game, VPN) có thể gặp. Checksum cộng dồn đã từ chối fragment, còn đường `SetSource`/`SetDestination` thì chưa.
- **Hướng làm:** parser đánh dấu fragment (flags/offset `& 0x3FFF`); NAT bỏ qua (thả nguyên hoặc cho đi Direct) mảnh không phải mảnh đầu, kèm test.
- **Vị trí:** `src/TqkLibrary.WinDivert/Packet/Models/ParsedPacket.cs:161` (`WritePort`), `Packet/PacketParser.cs`, `TqkLibrary.WinDivert.Redirect/NatRedirectMiddleware.cs`.
- **Ngày ghi:** 2026-10-09 (phát hiện khi phân tích checksum cộng dồn).

### Đường full của pump còn cấp phát 230–600 B mỗi gói

- **Vấn đề:** đường bypass đã không cấp phát (IpAddressKey), nhưng gói đi đường full vẫn tạo `PacketContext` (`PacketPump.cs:184`), `ParsedPacket`, một `byte[]` + `IPAddress` mỗi lần đọc `Source`/`Destination` (`ParsedPacket.cs:26`, header Ipv4/Ipv6), `GetAddressBytes()` trong `WriteIp`, và `NatEntry`/`Slot` mới mỗi gói trong `NatTable.Upsert`. Log đo ngày 2026-10-09: pump `*-reply` khoảng 230–600 B/gói.
- **Vì sao:** chỉ ảnh hưởng traffic đi qua proxy (không ảnh hưởng game Direct), nhưng tải nặng qua proxy sẽ đẩy GC gen0 lên, mà GC dừng cả thread pump.
- **Hướng làm:** NAT dùng `IpAddressKey` và FlowKey dựng từ key; `Upsert` giữ slot cũ khi entry không đổi (đọc kỹ `Slot`/`MarkClosed` vì thay slot đang reset hạn); cân nhắc dùng lại `PacketContext`.
- **Ngày ghi:** 2026-10-09.

### Gợi ý lõi cho pump trên máy nhiều processor group

- **Vấn đề:** máy > 64 logical processor có nhiều group; `PumpCoreHints` có thể gán ideal processor ở group khác với group của thread, `SetThreadIdealProcessorEx` thất bại (chỉ log Debug, pump vẫn chạy). Ranking cũng không lọc theo affinity của process.
- **Vị trí:** `src/TqkLibrary.WinDivert/Pipeline/Helpers/PumpCoreHints.cs`.
- **Ngày ghi:** 2026-10-09 (finding review).

### A8. Mode nghe socket quét bảng kernel hai lần cho mỗi pid mới (Vừa)

- **Vấn đề:** `AcceptPid` gọi `_shouldTrackProcess(pid)` (→ `ProcessRuleTracker.TryAttach` → raise `ProcessAttached` → ghi `Channel` của `TrackedPidQueue`) trước khi ghi `_pidDecisions[pid]`. Consumer của hàng đợi gọi `AddProcess` lọt vào khe đó thì `PrePopulateForPid` chạy lần hai (quét bảng toàn máy). Luồng pump đã hết phần nặng (không còn `RebuildResolver`, `AddTrackedProcessId` chỉ ghi một `Channel`), lần quét thứ hai đã dời sang luồng consumer và thường tự thoát sớm vì `AddProcess` thấy `already.Accepted`, nhưng đó là may, không phải bảo đảm.
- **Vị trí:** [SocketTracker.cs:260](../src/TqkLibrary.WinDivert/Flow/SocketTracker.cs#L260) (callback), [SocketTracker.cs:268](../src/TqkLibrary.WinDivert/Flow/SocketTracker.cs#L268) (ghi verdict), [SocketTracker.cs:287-298](../src/TqkLibrary.WinDivert/Flow/SocketTracker.cs#L287-L298) (`AddProcess`), [RedirectEngine.cs:495](../../../src/ProxyDivert.Core/Engine/RedirectEngine.cs#L495) (`OnProcessAttached`).
- **Vì sao:** quét bảng ngay trên đường trễ SYN→accept, đúng thứ đã tối ưu ngày 2026-09-07. `TrackedPidQueueTests` chỉ phủ hàng đợi, chưa phủ ca này.
- **Cách sửa:** sửa ở submodule WinDivert: ghi verdict trước khi gọi callback, hoặc `AddProcess` bỏ qua khi `AcceptPid` đang xử lý cùng pid; hoặc `ShouldRedirect` trả verdict thay vì raise sự kiện trong callback.
- **Ngày ghi:** 2026-09-08 (kiểm lại 2026-09-11).

### B5. UDP relay khoá upstream theo cổng nguồn, đích đóng băng lần đầu (Vừa)

- **Vấn đề:** `GetOrAdd(UpstreamKey(srcPort, family), _ => new UdpUpstream(entry.OriginalDestination))`: một socket UDP nói với nhiều đích (DNS nhiều server, QUIC, STUN) thì datagram thứ hai trở đi gửi sai địa chỉ. `_upstreams` không bao giờ evict. Trong ProxyDivert nhánh này chỉ chạm khi `HandleUdpDatagram` trả payload ở trường hợp Direct-sau-redirect hiếm ([UdpFlowRouter.cs](../../../src/ProxyDivert.Core/Engine/UdpFlowRouter.cs)), còn proxy/VPN đi qua `UdpProxyForwarder`; vẫn là lỗi thư viện.
- **Vị trí:** [UdpRelayServer.cs:91](../src/TqkLibrary.WinDivert.Redirect/UdpRelayServer.cs#L91), [:103](../src/TqkLibrary.WinDivert.Redirect/UdpRelayServer.cs#L103) (`UpstreamKey`).
- **Cách sửa:** gửi thẳng `SendAsync(payload, entry.OriginalDestination)` trên một socket theo cổng, thêm idle-eviction.
- **Ngày ghi:** 2026-09-08.

### B14. Nhóm mức Thấp (WinDivert)

- **Vấn đề:** các lỗi nhỏ trong submodule, mỗi gạch một việc:
  - Parser không kiểm đủ byte cho header TCP/UDP, không xét fragment: [PacketParser.cs:20-24](../src/TqkLibrary.WinDivert/Packet/PacketParser.cs#L20-L24). Đã có `ihl < 20 || ihl > length`; còn thiếu `ihl + 20/8 <= length` và bỏ qua fragment-offset != 0. `Tcp`/`Udp` view đọc thẳng tại `TransportHeaderOffset` không kiểm biên ([ParsedPacket.cs:20-21](../src/TqkLibrary.WinDivert/Packet/Models/ParsedPacket.cs#L20-L21)), buffer pump dùng lại nên đọc rác của gói trước. Gắn với mục "Mảnh IPv4 thứ hai trở đi" ở trên.
  - IPv6 extension header không được duyệt, gói TCP đứng sau Hop-by-Hop bị cho qua không redirect: [PacketParser.cs:28-33](../src/TqkLibrary.WinDivert/Packet/PacketParser.cs#L28-L33). Duyệt chuỗi extension chuẩn hoặc Drop rõ ràng.
  - `ExpireTick == 0` trùng giá trị thật một lần mỗi 49.7 ngày: [SocketTracker.cs:665](../src/TqkLibrary.WinDivert/Flow/SocketTracker.cs#L665), [TcpFlowState.cs:7](../src/TqkLibrary.WinDivert/Flow/Models/TcpFlowState.cs#L7). Dùng `long?` hoặc `bool IsClosing`.
  - `SocketClose` lặp lại cho cùng flow TCP gia hạn `ExpireTick` mãi: [SocketTracker.cs:658-668](../src/TqkLibrary.WinDivert/Flow/SocketTracker.cs#L658-L668). (Phần UDP đã xử lý: `SocketClose` giờ gỡ bind UDP.)
  - Bind UDP trên ANY che phủ mọi tiến trình cùng cổng: [SocketTracker.cs:192-194](../src/TqkLibrary.WinDivert/Flow/SocketTracker.cs#L192-L194).
  - `DnsMessageParser` cấp phát `List(answerCount)` theo số do gói tin quyết định: [DnsMessageParser.cs:55](../src/TqkLibrary.WinDivert.SecureDns/DnsMessageParser.cs#L55). `Math.Min(answerCount, 64)`.
  - `RelayToAsync` không truyền half-close: [RedirectedTcpConnection.cs:84](../src/TqkLibrary.WinDivert.Redirect/Models/RedirectedTcpConnection.cs#L84). `Shutdown(Send)` phía còn lại rồi đợi chiều kia.
  - `TcpRelayServer.Dispose` dispose CTS khi handler còn chạy: [TcpRelayServer.cs:198-211](../src/TqkLibrary.WinDivert.Redirect/TcpRelayServer.cs#L198-L211) (đã có danh sách kết nối đóng trước, cần kiểm lại còn hở không).
  - `ProcessTreeMonitor.Dispose` không gỡ event ([ProcessTreeMonitor.cs:132](../src/TqkLibrary.WinDivert.ProcessControl/ProcessTreeMonitor.cs#L132)); `SemaphoreSlim` trong [DnsOverHttpsMiddleware.cs:114](../src/TqkLibrary.WinDivert.SecureDns/DnsOverHttpsMiddleware.cs#L114) không dispose.
  - `SuspendedProcess.Resume()` sau `Dispose()` ném `Win32Exception` khó hiểu: [SuspendedProcess.cs:29-45](../src/TqkLibrary.WinDivert.ProcessControl/SuspendedProcess.cs#L29-L45). Set `_resumed = true` trong `Dispose`.
  - Dead code: `WinDivertNative.RecvEx`/`HelperCompileFilter`/`Ntohs`/`Htons` ([WinDivertNative.cs:35-90](../src/TqkLibrary.WinDivert/Native/WinDivertNative.cs#L35-L90)), `IpHlpApi.EnumerateProcessTcpFlows`/`EnumerateProcessUdpBinds` ([IpHlpApi.cs:115-122](../src/TqkLibrary.WinDivert/Native/IpHlpApi.cs#L115-L122)). Lưu ý: `RecvEx` và `HelperCompileFilter` có thể được dùng lại bởi hai mục "Pump NETWORK: nhận gói theo lô" và "Test filter" ở trên; kiểm trước khi xoá.
- **Vị trí:** xem từng gạch.
- **Vì sao:** hiếm gặp hoặc chỉ tốn tài nguyên.
- **Ngày ghi:** 2026-09-08 (kiểm lại 2026-09-11 và 2026-10-09).

### `ISocketTracker.ProcessPumpStopped` chưa được chuyển lên `IProcessRedirector`

- **Vấn đề:** từ B17, pump SOCKET bỏ cuộc thì gỡ pid khỏi `_pidHandles` và bắn `ISocketTracker.ProcessPumpStopped(pid)`, nhưng `ProcessRedirector` không chuyển tiếp sự kiện này nên app (ProxyDivert.Core) chưa nghe được để mở lại hoặc báo; hiện chỉ có log Error. Lần `AddProcess` kế tiếp cho pid đó (vd watcher thấy lại tiến trình) giờ đã mở được handle mới.
- **Vị trí:** `src/TqkLibrary.WinDivert/Flow/SocketTracker.cs` (`OnPumpGaveUp`), `src/TqkLibrary.WinDivert.Redirect/ProcessRedirector.cs` (`StartCore`), `Interfaces/IProcessRedirector.cs`.
- **Ngày ghi:** 2026-11-25.

### E1.3. Sở hữu chỉ nằm trong doc, không trong kiểu, WinDivert (Should)

- **Vấn đề:** `IPacketPumpFactory.Create` ghi "pump takes ownership of handle" chỉ trong doc; `ProcessRedirectorFactory` luôn tạo `IDnsCacheLookup` dù `EnableDnsLookup=false`; 7 dòng `?.Dispose()` tay trong `ProcessRedirector`; `Func<IReverseDnsTable>` tự viết trong `RedirectServiceCollectionExtensions`; `AddTrackedProcessId` ném trước `Start`; `SocketTracker.Dispose` chờ tuần tự 1s/handle.
- **Vị trí:** `src/TqkLibrary.WinDivert/Pipeline/Interfaces/IPacketPumpFactory.cs`, `.../TqkLibrary.WinDivert.Redirect/ProcessRedirectorFactory.cs`, `ProcessRedirector.cs`, `DependencyInjection/RedirectServiceCollectionExtensions.cs`, `.../Flow/SocketTracker.cs` (`Dispose`).
- **Cách sửa:** `IProcessRedirectorFactory.Create` mở một `IServiceScope` cho session, mọi thứ per-session đăng ký Scoped, `Dispose` = dispose scope (DI đảm bảo thứ tự ngược). Queue pid trước `Start` rồi flush; `Dispose` shutdown tất cả rồi `WaitAll` một lần. Rủi ro thấp.
- **Ngày ghi:** 2026-09-08.

### E2.2. `SocketTracker` ôm 8 mối quan tâm, file churn nhất lib WinDivert (Must)

- **Vấn đề:** [SocketTracker.cs](../src/TqkLibrary.WinDivert/Flow/SocketTracker.cs) gồm: handle per-pid, mode machine-wide + `_pidDecisions`, bảng TCP/UDP, decode socket event, reconcile kernel + throttle, cleanup loop, pre-populate. Có 7 điểm rẽ `IsMachineWide`; `FakeTracker` trong test phải implement 13 member chỉ để test NAT (`src/ProxyDivert.Core.Tests/NatRedirectMiddlewareEscapedFlowTests.cs`).
- **Vì sao:** mọi lỗi race SYN/attach/trễ quét/RemoveProcess đều đổ về file này; reconcile gọi `IpHlpApi` static nên không test được.
- **Cách sửa:** `FlowTable` (thuần, 4 dictionary + `Record/Close/Reap(now)` + 4 event, test không cần driver); `SocketEventPump` (decode `WinDivertAddress` → `SocketEvent` record); `IKernelConnectionTable` bọc `IpHlpApi` + `KernelReconciler` (throttle, dùng `IClock`); `IProcessScope` (strategy) với `PerProcessHandleScope`/`MachineWideScope` xoá mọi `if (IsMachineWide)`; `SocketTracker` còn façade ~120 dòng; `ISocketTracker` thu về `IFlowLookup` + `IProcessScope`. Thứ tự: `FlowTable` (viết test trước khi dời, giữ ngữ nghĩa `TryAdd else overwrite` và `wasLive`) → kernel table → scope. Giải quyết luôn B4 (khoá `(pid, startTime)` trong `MachineWideScope`) và A8.
- **Ngày ghi:** 2026-09-08.

### E2.3. `NatRedirectMiddleware` gộp NAT + policy cổng + escaped flow + reset + dedupe log (Should)

- **Vấn đề:** ctor 11 tham số, whitelist cổng, escaped flow, dựng RST cùng nằm trong một class (`src/TqkLibrary.WinDivert.Redirect/NatRedirectMiddleware.cs`).
- **Cách sửa:** dùng chính pipeline: `TrackedFlowGate` (tracked? reconcile? dstPort filter, gắn `FlowOwner` vào context) → `EscapedFlowMiddleware` (pass/drop/reset) → `NatRewriteMiddleware` (chỉ Upsert + rewrite). Cần `PacketContext.Items` hoặc thuộc tính typed `FlowOwner?`. Test escaped flow sẵn có chạy lại được.
- **Ngày ghi:** 2026-09-08.

### E2.4. `ProcessRedirector` vừa orchestrator, vừa builder pipeline, vừa chính sách IPv6, vừa tuning driver (Should)

- **Vấn đề:** build pipeline v4/v6 lặp gần y hệt; quyết định IPv6 fallback và tham số queue driver nằm trong `src/TqkLibrary.WinDivert.Redirect/ProcessRedirector.cs`.
- **Cách sửa:** `NetworkPipelineFactory.Create(AddressFamily, RelayEndpoints, features)` gọi 2 lần; `Ipv6Policy.Resolve(requested, osSupportsIpv6, relayHasV6)` thuần, test được; `NetworkHandleOptions` truyền vào handle factory. Các hàm `Start*Pump` biến mất.
- **Ngày ghi:** 2026-09-08.

### E3.4. v4/v6: cặp field nhân đôi và cờ `isIpv6` xuyên 20 file, WinDivert (Should)

- **Vấn đề:** `_listener/_listenerV6`, `Port/PortV6` trong `TcpRelayServer`/`UdpRelayServer`; `RelayPorts` 4 int + `For(bool, bool)`; 4 thuộc tính port trên `IProcessRedirector`; `NatKey.IsIpv6` bool; `IsIpv6 ? Ipv6.X : Ipv4.X` trong `ParsedPacket`; 15 lần `isIpv6` trong `NatRedirectMiddleware`.
- **Vì sao:** lỗi "NAT v4/v6 ghi đè nhau" đã từng xảy ra vì family là cờ rời phải nhớ truyền (`src/ProxyDivert.Core.Tests/Ipv6RoutingTests.cs`).
- **Cách sửa:** value object `RelayEndpoint(IpProtocol, AddressFamily, IPAddress Loopback, int Port)` + `RelayEndpointSet.TryGet(protocol, family)`; `TcpRelayServer` = composite của N `TcpRelayListener(loopbackAddress, nat, handler)`, `UdpRelayServer` tương tự; `NatKey(IpProtocol, AddressFamily, ushort)`; `IIpHeaderView { Family; Source; Destination; HeaderLength; Protocol }` do hai view implement, `ParsedPacket.Ip` trả về nó. Thứ tự: NatKey/INatTable (cơ học, có test) → relay listener → header view → vòng lặp trong ProcessRedirector. Hai family hai socket loopback riêng là bắt buộc, composite giữ đúng điều đó.
- **Ngày ghi:** 2026-09-08.

### E3.5. tcp/udp là `byte` magic 6/17 và `isTcp ? :` rải rác, WinDivert (Should)

- **Vấn đề:** `FlowKey.Protocol` là `byte` dù có `IpProtocol` enum; literal 6/17 trong `SocketTracker`, `NatRedirectMiddleware`, `Ipv6BlockMiddleware`, `UdpRelayServer`; ba cặp `isTcp ? tracker.IsTrackedTcp : IsTrackedUdp` trong `NatRedirectMiddleware`.
- **Cách sửa:** `FlowKey`/`NatKey`/`NatEntry`/`INatTable` dùng `IpProtocol`; `ITransportFlowPolicy { IsTracked; TryGetOwner; MayRedirectNow }` với `TcpFlowPolicy`/`UdpFlowPolicy` chọn một lần theo `p.Protocol`; "UDP hỏi `ShouldRedirectUdp` còn TCP không" thuộc `UdpFlowPolicy`.
- **Ngày ghi:** 2026-09-08.

### E4.3. `RedirectOptions` là túi delegate thay cho interface host, WinDivert (Should)

- **Vấn đề:** 4 delegate trong `RedirectOptions`; consumer implement cả 4 bằng method private trên một class (`src/ProxyDivert.Core/Engine/RedirectEngine.cs`); Demo phải tạo `redirectorRef` gán sau `Create` để handler gọi ngược; mode chọn bằng null-ness của `Func` (`ISocketTrackerFactory`); sentinel `ProcessId = 0` làm `NatEntry.ProcessId = 0` bị stamp lặng lẽ khi tracker miss (`NatRedirectMiddleware`).
- **Cách sửa:** `IRedirectHost { HandleTcpAsync(session, conn, ct); UdpVerdict HandleUdp(dg); bool ShouldRedirectUdp(target); }` + `IProcessSelector` + `ProcessScopeKind` enum tường minh; `RedirectOptions` chỉ còn dữ liệu; `InitialProcessIds` thay sentinel 0, bỏ fallback root pid. Giữ overload extension nhận lambda cho Demo.
- **Ngày ghi:** 2026-09-08.

### E4.4. Packet model: `WinDivertAddress` rò lên middleware, `MarkModified` tách rời (Should)

- **Vấn đề:** `PacketContext.Address` là struct native public, `IPacketInjector.Inject(..., in WinDivertAddress)`, magic `IfIdx = 1`, dựng address inbound trùng ở `NatRedirectMiddleware` và `DnsOverHttpsMiddleware`. `SetSource/SetDestination` ghi buffer nhưng phải nhớ gọi `MarkModified` riêng; setter trên header view struct không có tác dụng (`TcpHeader.cs`).
- **Vị trí:** `src/TqkLibrary.WinDivert/Pipeline/Models/PacketContext.cs`, `Pipeline/PacketPump.cs`, `Packet/Models/ParsedPacket.cs`, `Packet/Models/TcpHeader.cs`.
- **Cách sửa:** value type `PacketRoute { Direction; Loopback; InterfaceRef; Family }` với factory `LoopbackOutbound(family)`/`InboundOn(iface)`; `PacketPump` là nơi duy nhất map sang `WinDivertAddress`; struct native `internal`. Bỏ setter trên view; ghi qua `ctx.Rewrite(...)` tự đặt `Modified`.
- **Ngày ghi:** 2026-09-08.

### E4.5. Redirect phụ thuộc cứng SecureDns/Inspection, không thêm được feature thứ 6 (Should)

- **Vấn đề:** `IReverseDnsTable` nằm trên interface session; `PeekableStream` (kiểu Inspection) nằm trên model `RedirectedTcpConnection`; `ProcessRedirector` new thẳng hai middleware DNS; `CapturesUdp` hard-code nhu cầu từng feature nên middleware user cần UDP khi `Protocols = Tcp` không bao giờ thấy gói UDP; `ConfigureNetworkPipeline` chỉ chèn sau NAT; doc NAT "must run first" mâu thuẫn thứ tự đăng ký thực. `DnsCacheLookup` (spawn `ipconfig`) nằm ở core `Flow/` với interface khác tên `IReverseDnsTable` dù cùng mục đích IP→tên.
- **Cách sửa:** `IRedirectFeature { NeedsUdpCapture; Families; Contribute(builder, PipelineStage, ctx) }` với `DnsSniffFeature`, `DohFeature`, `BlockTargetUdpFeature`; `ProcessRedirector` lặp `options.Features` và ghép filter driver từ `NeedsUdpCapture`; `PipelineStage` enum (PreNat/Nat/PostNat) để ràng buộc thứ tự thành kiểu; `ReverseDns` rời khỏi interface session; `IPeekableStream` ở core. `IAddressNameLookup` chung cho `ReverseDnsTable` và `DnsCacheLookup` (dời sang SecureDns), `CompositeNameLookup`. `Ipv6BlockMiddleware`, `BlockTargetUdpMiddleware` chỉ phụ thuộc `ISocketTracker`, dời về core làm "per-process firewall". Mẫu để nhân bản: `IHostNameParser` strategy list của Inspection.
- **Ngày ghi:** 2026-09-08.

### E4.7. Nhóm Nice (abstraction)

- **Phạm vi:** chỉ các gạch thuộc TqkLibrary.WinDivert; các gạch còn lại của mục này nằm ở backlog app ProxyDivert (repo cha, `docs/Backlog-vi.md`, cùng tiêu đề).
- **Vấn đề:**
  - `IProcessRedirector` phơi `Nat`, `TcpConnectionOpened/Closed`, `TrackedProcessIds` không consumer nào dùng. Tách `IRedirectDiagnostics`.
  - Naming trong WinDivert: 4 "tracker" (`SocketTracker`/`ProcessRuleTracker`/`ConnectionTracker`/`IProcessTreeMonitor`), `AddTrackedProcessId` vs `AddProcess`, file `Ipv4Header.cs` chứa `Ipv4HeaderView`, consumer phải `using` 7 namespace con `.Interfaces/.Enums/.Models` (`RedirectEngine.cs`). NuGet nên phẳng namespace.
- **Vị trí:** xem từng gạch; `IProcessRedirector.cs` ở `src/TqkLibrary.WinDivert.Redirect/Interfaces/`.
- **Ngày ghi:** 2026-09-08. Xen kẽ khi chạm file liên quan, không lên lịch riêng.

### E6.8. Nhóm nhỏ trùng lặp (Nice)

- **Phạm vi:** chỉ các gạch thuộc TqkLibrary.WinDivert; các gạch còn lại của mục này nằm ở backlog app ProxyDivert (repo cha, `docs/Backlog-vi.md`, cùng tiêu đề).
- **Vấn đề:**
  - Ghi header IPv4 tay ở 3 nơi: `TcpResetPacketBuilder.cs`, `DnsOverHttpsMiddleware.cs`, VpnClient `Ipv4.Build`. Trong WinDivert: `Ipv4PacketWriter`/`Ipv6PacketWriter` ở core `Packet/`; không tham chiếu VpnClient.
- **Vị trí:** xem từng gạch.
- **Ngày ghi:** 2026-09-08.

### E7.2. Sự kiện `ISocketTracker` bắn từ 3 ngữ cảnh thread mà interface không nói (Should)

- **Vấn đề:** sự kiện bắn từ socket pump, từ thread gọi `RemoveProcess` (UI), và từ NETWORK pump qua reconcile; `ISocketTracker` không có ghi chú thread trong khi `ITcpRelayServer` có; `ProcessRedirector` forward event ra host nên host chậm sẽ chặn pump.
- **Vị trí:** `src/TqkLibrary.WinDivert/Flow/SocketTracker.cs`, `Flow/Interfaces/ISocketTracker.cs`.
- **Cách sửa:** sau E2.2, mọi mutation đi qua một `Channel<FlowMutation>` do thread sở hữu `FlowTable`; event bắn từ đúng một thread; doc một dòng. Lợi ích chính là hợp đồng rõ, không phải hiệu năng.
- **Ngày ghi:** 2026-09-08.

### E9.1. Test của WinDivert nằm trong repo app, submodule 0 test, thiếu seam bảng kernel (Must)

- **Vấn đề:** 7 file test của lib (`NatRedirectMiddlewareEscapedFlowTests`, `EscapedFlowBlocklistTests`, `Ipv6RoutingTests`, `DnsMessageParserTests`, `PeekableStreamTests`, `TcpResetPacketBuilderTests`, `TlsClientHelloParserTests`) nằm ở `src/ProxyDivert.Core.Tests`; `IpHlpApi` static gọi thẳng từ `SocketTracker` (`PrePopulateForPid`, reconcile). Submodule đã có project test đầu tiên `TqkLibrary.WinDivert.Tests` (không cần admin) nhưng 7 file trên chưa dời và seam bảng kernel chưa có.
- **Vì sao:** không publish/validate NuGet độc lập được; reconcile/pre-populate (nguồn mọi bug race) không test được dù `IWinDivertHandleFactory` đã fake được.
- **Cách sửa:** dời 7 file vào `src/TqkLibrary.WinDivert.Tests` (+ `.Redirect.Tests`), `RawTcpPackets.cs` thành helper chung; `IKernelConnectionTable` + `IClock` inject qua `ISocketTrackerFactory`. Test được ngay không cần driver: `PacketPump` (fake handle), relay servers (loopback thật + `NatTable` seed), `DnsOverHttpsMiddleware` (fake resolver + recording injector), `ProcessRedirector` (5 factory fake).
- **Ngày ghi:** 2026-09-08.
