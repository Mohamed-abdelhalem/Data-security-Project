using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            char[] English_alphabetic = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            string KEY_STRING = "";
            bool found = false;
            cipherText = cipherText.ToLower();
            int var1 = 0;
            while (var1 < 26)
            {
                int var2 = 0;
                while (var2 < plainText.Length)
                {
                    if (English_alphabetic[var1] == plainText[var2])
                    {
                        KEY_STRING += cipherText[var2];
                        found = true;
                        break;
                    }
                    else
                    {
                        found = false;
                    }
                    if (var2 == plainText.Length - 1)
                    {
                        found = false;
                    }
                    var2++;
                }
                if (!found)
                {
                    KEY_STRING += '0';
                }
                var1++;
            }
            char[] arr = KEY_STRING.ToCharArray();
            bool found2 = false;
            int var6 = 0;
            do //(int i = 0; i < 26; i++)
            {
                if (arr[var6] == '0')
                {
                    int var3 = 0;
                    while (var3 < 26)
                    {
                        int var4 = 0;
                        while (var4 < KEY_STRING.Length)
                        {
                            if (English_alphabetic[var3] == arr[var4])
                            {
                                found2 = true;
                                break;
                            }
                            else
                            {
                                found2 = false;
                            }
                            if (var4 == KEY_STRING.Length - 1)
                            {
                                found2 = false;
                            }
                            var4++;
                        }
                        if (!found2)
                        {
                            arr[var6] = English_alphabetic[var3];
                        }
                        var3++;
                    }
                }
                var6++;
            } while (var6 < 26);
            string key = "";
            int variable = 0;
            while (variable < arr.Length)
            {
                key += arr[variable];
                variable++;
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            Dictionary<char, char> dictionary;

            dictionary = new Dictionary<char, char>();

            char[] English_alphabetic = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            int first_variable = 0;
            while (first_variable < 26)
            {
                dictionary.Add(key[first_variable], English_alphabetic[first_variable]);
                first_variable++;
            }

            string Plain_Text = "";
            cipherText = cipherText.ToLower();
            int second_variable = 0;
            while (second_variable < cipherText.Length)
            {
                if (cipherText[second_variable] != ' ')
                {
                    Plain_Text += dictionary[cipherText[second_variable]];
                }
                second_variable++;
            }
            return Plain_Text;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            char[] cipher_text = new char[plainText.Length];
            int third_variable = 0;
            while (third_variable < plainText.Length)
            {
                if (plainText[third_variable] == ' ')
                {
                    cipher_text[third_variable] = ' ';
                }

                else
                {
                    int j = plainText[third_variable] - 97;
                    cipher_text[third_variable] = key[j];
                }
                third_variable++;
            }
            return new string(cipher_text);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            cipher = cipher.ToLower();
            int c = 0;
            Dictionary<char, int> d1;
            d1 = new Dictionary<char, int>();


            Dictionary<char, char> d2;
            d2 = new Dictionary<char, char>();

            char[] AlphaFrequency = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'd', 'l', 'c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j', 'x', 'q', 'z' };
            for (char i = 'a'; i <= 'z'; i++)
            {
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (i == cipher[j])
                    {
                        c++;
                    }
                }
                d1.Add(i, c);
                c = 0;
            }

            char[] x = new char[26];
            int k = 0;
            foreach (KeyValuePair<char, int> l in d1.OrderByDescending(key => key.Value))
            {
                //Console.WriteLine("{0}   {1}", l.Key, l.Value);
                x[k] = l.Key;
                k++;

            }


            for (int i = 0; i < 26; i++)
            {
                d2.Add(x[i], AlphaFrequency[i]);
            }


            string PlainText = "";


            for (int j = 0; j < cipher.Length; j++)
            {
                foreach (KeyValuePair<char, char> mm in d2)
                {
                    if (cipher[j] == mm.Key)
                        PlainText += mm.Value;
                }
            }
            return PlainText;
        }
    }
}
    
