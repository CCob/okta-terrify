using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using static OktaCommon.BCrypt.PInvoke;

namespace OktaCommon.BCrypt {

    public class SafeBCryptAlgHandle : SafeBCryptHandle {

        public SafeBCryptAlgHandle() {

        }

        public SafeBCryptAlgHandle(bool ownsHandle) : base(ownsHandle) {
        }
        protected override bool ReleaseHandle() {
            BCryptCloseAlgorithmProvider(handle);
            SetHandleAsInvalid();
            return true;
        }
    }

    public class SafeBCryptKeyHandle : SafeBCryptHandle {

        public SafeBCryptKeyHandle() {

        }

        public SafeBCryptKeyHandle(bool ownsHandle) : base(ownsHandle) {
        }

        protected override bool ReleaseHandle() {
            BCryptDestroyKey(handle);
            SetHandleAsInvalid();
            return true;
        }

    }

    public abstract class SafeBCryptHandle : SafeHandleZeroOrMinusOneIsInvalid {

        public SafeBCryptHandle() : this(true) {

        }

        public SafeBCryptHandle(bool ownsHandle) : base(ownsHandle) {
        }

    }

    public static class PInvoke {
        public struct BCRYPT_KEY_LENGTHS_STRUCT {
            public uint dwMinLength;
            public uint dwMaxLength;
            public uint dwIncrement;
        }

        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
            public uint cbSize;
            public uint dwInfoVersion;
            public IntPtr pbNonce;
            public uint cbNonce;
            public IntPtr pbAuthData;
            public uint cbAuthData;
            public IntPtr pbTag;
            public uint cbTag;
            public IntPtr pbMacContext;
            public uint cbMacContext;
            public uint cbAAD;
            public ulong cbData;
            public uint dwFlags;
        }       

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptSetProperty(SafeBCryptHandle hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, uint cbInput, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptGetProperty(SafeBCryptHandle hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint BCryptOpenAlgorithmProvider(out SafeBCryptAlgHandle phAlgorithm, string pszAlgId, [Optional] string pszImplementation, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptGenerateSymmetricKey(SafeBCryptAlgHandle hAlgorithm, out SafeBCryptKeyHandle phKey, [Optional] IntPtr pbKeyObject, [Optional] uint cbKeyObject, byte[] pbSecret, uint cbSecret, uint dwFlags = 0);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptDecrypt(SafeBCryptKeyHandle hKey, byte[] pbInput, uint cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, uint cbIV, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll", SetLastError = false, ExactSpelling = true)]
        public static extern uint BCryptDestroyKey(IntPtr keyHandle);
    }  
}
