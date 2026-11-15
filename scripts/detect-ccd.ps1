Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Lpi {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetLogicalProcessorInformation(IntPtr buf, ref uint len);
    public enum REL { ProcessorCore = 0, NumaNode = 1, Cache = 2, Package = 3 }
    public enum CACHE_TYPE { Unified, Instruction, Data, Trace }
    // SYSTEM_LOGICAL_PROCESSOR_INFORMATION, fixed 32 bytes on x64
    [StructLayout(LayoutKind.Sequential)]
    public struct INFO {
        public IntPtr ProcessorMask;      // 0
        public REL Relationship;          // 8
        public uint Padding;              // 12
        public byte CacheLevel;           // 16 (union: Cache)
        public byte CacheAssociativity;   // 17
        public ushort CacheLineSize;      // 18
        public uint CacheSize;            // 20
        public CACHE_TYPE CacheType;      // 24
        public uint CachePad;             // 28 -> 32
    }
}
'@

$len = 0
[void][Lpi]::GetLogicalProcessorInformation([IntPtr]::Zero, [ref]$len)
if ($len -eq 0) { throw "GetLogicalProcessorInformation failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
$buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($len)
[void][Lpi]::GetLogicalProcessorInformation($buf, [ref]$len)

$count = $len / 32
$seen = @{}
for ($n = 0; $n -lt $count; $n++) {
    $i = [Runtime.InteropServices.Marshal]::PtrToStructure(
        [IntPtr]::new($buf.ToInt64() + $n * 32), [type][Lpi+INFO])
    if ($i.Relationship -ne [Lpi+REL]::Cache) { continue }
    $key = "{0}|{1}|{2}" -f $i.CacheLevel, $i.CacheSize, $i.ProcessorMask.ToInt64()
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    if ($i.CacheSize -ge 256KB) {
        "{0} L{1} {2} MB  mask=0x{3:X}" -f $i.CacheType, $i.CacheLevel,
            [math]::Round($i.CacheSize / 1MB), $i.ProcessorMask.ToInt64()
    }
}
