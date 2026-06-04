using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Redirect;

public delegate Task TcpConnectionHandler(RedirectedTcpConnection connection, CancellationToken ct);
