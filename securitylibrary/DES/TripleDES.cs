using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            // throw new NotImplementedException();
            string plain_text = string.Empty;
            DES d = new DES();
            plain_text = d.Decrypt(cipherText, key[0]);
            plain_text = d.Encrypt(plain_text, key[1]);
            plain_text = d.Decrypt(plain_text, key[0]);
            return plain_text;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            //throw new NotImplementedException();
            string cipherT_ext = string.Empty;
            DES d = new DES();
            cipherT_ext = d.Encrypt(plainText, key[0]);
            cipherT_ext = d.Decrypt(cipherT_ext, key[1]);
            cipherT_ext = d.Encrypt(cipherT_ext, key[0]);
            return cipherT_ext;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}