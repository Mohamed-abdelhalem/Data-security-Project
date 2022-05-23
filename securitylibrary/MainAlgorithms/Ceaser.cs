using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string output_Encrypt = string.Empty;

            for(int i = 0; i< plainText.Length; i++)
            {
                if (char.IsUpper(plainText[i]))
                    {
                    output_Encrypt += (char) ( ( (plainText[i] + key - 65) % 26 )+ 65);
                    }
                else
                    {
                    output_Encrypt += (char) ( ( (plainText[i] + key - 97) % 26) + 97);
                    }
            }

            return output_Encrypt;
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            string output_Decrypt = string.Empty;
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (char.IsUpper(cipherText[i]))
                {
                    int x = (cipherText[i] - key - 65);
                    if (x < 0)
                    {
                        int y = 26 - ((x * -1) % 26);
                        output_Decrypt += (char)(y % 26 + 65);
                    }
                    else
                    {
                        output_Decrypt += (char) ((cipherText[i] - key - 65) % 26 + 65);
                    }

                }
                else
                {
                    int m = (cipherText[i] - key - 97);
                    if (m < 0)
                    {
                        int yy = 26 - ((m * -1) % 26);
                        output_Decrypt += (char)(yy % 26 + 97);
                    }
                    else
                    {
                        output_Decrypt += (char)((cipherText[i] - key - 97) % 26 + 97);
                    }
                }
            }
            return output_Decrypt;
        }

        public int Analyse(string plainText, string cipherText)
        {
            //  throw new NotImplementedException();
            //  ABCDEFGHIJKLMNOPQRSTWXYZ 0=>25
            //     COMPUTER
            //     KWUXCBMZ   K = 10 , C = 2 => KEY = 8
            //     from test  P = 15 , M = 12 => KEY = 3
            char[] alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
            string mo = cipherText.ToUpper();
            string mn = plainText.ToUpper();
            int counter_plain = 0 , counter_cipher = 0  , key;
            for (int i = 0; i < alpha.Length; i++)
            {
                char ch_cipher = mo[0];       
                if(ch_cipher == alpha[i])
                {
                    counter_cipher = i;
                    break;
                }
                else
                continue;
            }
            for (int j = 0; j < alpha.Length; j++)
            {
                char ch_plain = mn[0];
                if (ch_plain == alpha[j])
                {
                    counter_plain = j;
                    break;
                }
                else
                    continue;
            }
            key =counter_cipher - counter_plain;
            if (key < 0)
                key += 26;


            return key;
        }
    }
}
