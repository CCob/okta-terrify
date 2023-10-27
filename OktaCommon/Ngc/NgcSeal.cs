using System;
using System.IO;
using System.Runtime.InteropServices;

namespace OktaCommon.Ngc {
    public class NgcSeal {

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct UnkPin {
            public uint Length;
            public uint UnkFlag;
            public string Pin;
            public UnkPin(NgcPin pin) {
                Pin = pin.ToString() + "\0";
                Length = (uint)Pin.Length * 2;
                UnkFlag = 0x46;                
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UnkPadding : IDisposable {
            public UnkPin UnkPin { get; private set; }
            IntPtr ptr;
            GCHandle handle;
            byte[] unkPinBytes;

            public UnkPadding(UnkPin unkPin) {
                UnkPin = unkPin;
                unkPinBytes = unkPin.ToBytes();
                handle = GCHandle.Alloc(unkPinBytes, GCHandleType.Pinned);
                ptr = handle.AddrOfPinnedObject();
            }

            public void Dispose() {
                if(handle != default) { 
                    handle.Free();
                    handle = default;
                    ptr = IntPtr.Zero;
                }                
                GC.SuppressFinalize(this);
            }
            
            public byte[] ToBytes() {
                using (var br = new BinaryWriter(new MemoryStream())) {

                    br.Write(0);
                    br.Write(1);
                    if(IntPtr.Size == 8)
                        br.Write((ulong)ptr);
                    else
                        br.Write((uint)ptr);
                    
                    return ((MemoryStream)br.BaseStream).ToArray();
                }

            }
        }  
    }
}
