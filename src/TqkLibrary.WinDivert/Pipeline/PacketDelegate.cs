using System.Threading.Tasks;

namespace TqkLibrary.WinDivert.Pipeline;

// The next stage in the chain. A middleware calls this to defer to the rest of the pipeline.
public delegate Task PacketDelegate(PacketContext context);
