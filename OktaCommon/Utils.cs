using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace OktaCommon {
    public static class Utils {

        public class RequireStruct<T> where T : struct { }
        public class RequireClass<T> where T : class { }

        public static string Base64Url(byte[] data) {
            char[] padding = { '=' };
            return Convert.ToBase64String(data).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Base64Url(string data) {
            string incoming = data.Replace('_', '/').Replace('-', '+');
            switch (data.Length % 4) {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return Convert.FromBase64String(incoming);            
        }

        public static string Hex(this byte[] ba, bool upper = false) {
            StringBuilder hex = new StringBuilder(ba.Length * 2);

            foreach (byte b in ba)
                if (upper)
                    hex.AppendFormat($"{b:X2}");
                else
                    hex.AppendFormat($"{b:x2}");

            return hex.ToString();
        }

        public static byte[] FromHex(this string hex) {
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++) {
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return raw;
        }

        public static string Repeat(this string text, uint n) {
            return string.Concat(Enumerable.Repeat(text, (int)n));        
        }

        public static byte[] ToBytes<T>(this T obj, RequireStruct<T> ignore = null) where T : struct {
            return ToNative(obj);
        } 

        public static byte[] ToBytes<T>(this T obj, RequireClass<T> ignore = null) where T : class {
            return ToNative(obj);
        }

        public static T ToStructure<T>(this IntPtr ptr)  {
            return Marshal.PtrToStructure<T>(ptr);
        }

        static byte[] ToNative(object obj) {
            var result = new byte[Marshal.SizeOf(obj)];
            GCHandle h = GCHandle.Alloc(result, GCHandleType.Pinned);
            Marshal.StructureToPtr(obj, h.AddrOfPinnedObject(), false);
            h.Free();
            return result;
        }

        public static byte[] AesDecrypt(byte[] encData, byte[] key, byte[] iv, CipherMode cipherMode = CipherMode.CBC) {
            using (var aes = new AesManaged()) {
                aes.IV = iv;
                aes.Key = key;
                aes.Mode = cipherMode;

                using (MemoryStream ms = new MemoryStream()) {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write)) {
                        cs.Write(encData, 0, encData.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
    }
}
