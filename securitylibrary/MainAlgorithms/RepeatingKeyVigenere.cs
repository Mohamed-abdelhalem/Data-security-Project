using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public void make_Vigenere_tableau(char[,] tableau)
        {
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            int cnt = 0;

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {                                 //shifting by 1 char
                    tableau[i, j] = alpha[(j + cnt) % 26];
                }
                cnt++;
            }
        }
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //table
            char[,] vigenere_tableau = new char[26, 26];
            make_Vigenere_tableau(vigenere_tableau);
            string key = "";



            for (int i = 0; i < cipherText.Length; i++)
            {
                int row_p = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (vigenere_tableau[j, 0] == plainText[i])
                    {
                        row_p = j;
                        break;
                    }
                }
                for (int j = 0; j < 26; j++)
                {
                    if (vigenere_tableau[row_p, j] == cipherText[i])
                    {
                        key += vigenere_tableau[0, j];
                        break;
                    }
                }
            }
            //  Console.WriteLine(key);
            int ind_c = key.Length;
            int inc;
            bool ch;
            //last ind exist first char plaintext
            for (int i = 0; i < key.Length; i++)
            {
                inc = i;
                ch = true;
                if (key[i] == key[0] && i > 0)
                {
                    /* ind_c = i;
                     char last_char = key[key.Length - 1];
                     Console.WriteLine(key.Length);
                     Console.WriteLine(ind_c);
                     //index of char stop to auto in key
                     int ind_stop = key.Length - ind_c;
                     ind_stop--;

                     if (last_char == key[ind_stop])
                     {
                         break;
                     }*/

                    for (int j = 0; j < i; j++) //start from index contain key[0] to len before key[i]
                    {
                        if (key[inc] != key[j]) //compare
                        {
                            ch = false;
                            break;
                        }
                        inc++;
                    }
                    if (ch == true)
                    {
                        ind_c = i;
                        break;
                    }
                }

            }

            //last char of key
            key = key.Remove(ind_c);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            //convert to lower case
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            //table
            char[,] vigenere_tableau = new char[26, 26];
            make_Vigenere_tableau(vigenere_tableau);
            string plaintext = "";


            for (int i = 0; i < cipherText.Length; i++)
            {
                int col_key = 0;

                for (int j = 0; j < 26; j++)
                {
                    if (vigenere_tableau[0, j] == key[i % (key.Length)])
                    {
                        col_key = j;
                        break;
                    }
                }

                for (int j = 0; j < 26; j++)
                {
                    if (vigenere_tableau[j, col_key] == cipherText[i])
                    {
                        plaintext += vigenere_tableau[j, 0];
                        break;
                    }

                }



            }
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();

            //convert to lower case
            plainText = plainText.ToLower();
            key = key.ToLower();
            //table
            char[,] vigenere_tableau = new char[26, 26];
            make_Vigenere_tableau(vigenere_tableau);

            string cipher = "";

            //edit key to repeating key
            int diff = plainText.Length - key.Length;
            for (int i = 0; i < (diff); i++)
            {
                key += key[i % (plainText.Length - 1)];
            }
            Console.WriteLine("edit key: " + key);
            char c1, c2;
            //looping in each char in plaintext
            for (int i = 0; i < plainText.Length; ++i)
            {
                c1 = plainText[i];
                c2 = key[i];
                int r = 0, c = 0;
                //looping vigenere_tableau to get intersection cell
                for (int l = 0; l < 26; ++l)//rows -->key
                {
                    for (int k = 0; k < 26; ++k)//columns -->plain
                    {
                        if (c1 == vigenere_tableau[0, k]) //cols
                        {
                            c = k;
                        }

                        if (c2 == vigenere_tableau[l, 0]) //rows
                        {
                            r = l;
                        }
                    }
                }
                cipher += vigenere_tableau[r, c];
            }
            return cipher;
        }
    }
}