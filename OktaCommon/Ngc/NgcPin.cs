using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PBKDF2;
using SharpDPAPI;

namespace OktaCommon.Ngc{
    public class NgcPin{

        byte[] value;
        byte[] initialEntropy = Encoding.UTF8.GetBytes("xT5rZW5qVVbrvpuA\0");

        public NgcPin(string value){

            if(value == null) {
                throw new ArgumentNullException("value");
            }

            this.value = Encoding.ASCII.GetBytes(value);
        }

        public NgcPin(byte[] value) {

            if (value == null) {
                throw new ArgumentNullException("value");
            }

            this.value = value;
        }

        public override string ToString(){           
            return value.Hex(true);                            
        }

        public byte[] Encode(bool includeNull = true) {
            return Encoding.Unicode.GetBytes(ToString() + (includeNull ? "\0" : ""));            
        }

        public byte[] DeriveEntropy(byte[] salt, int rounds) {
            var pbkdf2 = new Pbkdf2(HMAC.Create("HMACSHA256"), Encode(false), salt, rounds);
            var pbkdf2Output = Encoding.Unicode.GetBytes(Helpers.ByteArrayToString(pbkdf2.GetBytes(32, "sha256"), true));
            return initialEntropy.Concat(SHA512.Create().ComputeHash(pbkdf2Output)).ToArray();
        }

        public byte[] DeriveEntropy() {
             return initialEntropy.Concat(SHA512.Create().ComputeHash(new MemoryStream(Encode(false)))).ToArray();
        }
    }
}
