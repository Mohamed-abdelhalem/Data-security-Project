using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //create 2D arr
            char[,] vigenere_tableau = new char[26, 26];
            make_Vigenere_tableau(vigenere_tableau);

            int len_cipher = cipherText.Length;
            // int len_plain = plainText.Length;

            string key = "";

            for (int i = 0; i < len_cipher; i++)
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

            //edit key
            /* for (int i = key.Length-1; i >=0; i--)
             {
                 int ind = 0, ch = 0;
                 for (int j = plainText.Length-1; j >0; j--)
                 {
                     if (key[i] == plainText[j])
                     {
                         if (ch == 0)
                         {
                             ch++;
                         }
                         break;
                     }

                 }
             }*/

            int ind_c = key.Length;
            int inc;
            bool ch = true;
            for (int i = 0; i < key.Length; i++)
            {
                inc = 0;
                ch = true;
                if (key[i] == plainText[0] && i > 0)
                {
                    /* ind_c = i;
                     char last_char = key[key.Length - 1];
                     //index of char stop to auto in key
                     int ind_stop = key.Length - ind_c;
                     ind_stop--;

                     if (last_char == key[ind_stop])
                     {
                         break;
                     }*/

                    for (int j = i; j < key.Length - i; j++) //start from index contain plaintext[0] to end
                    {
                        if (plainText[inc % (plainText.Length - 1)] != key[j]) //compare
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
            /*if (key.Contains(plainText[0]))
             {
             int ind = key.IndexOf(plainText[0]);
             key = key.Remove(ind);
             }*/


            //Console.WriteLine("key: " + key);

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //convert to lower
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            //table
            char[,] vigenere_tableau = new char[26, 26];
            make_Vigenere_tableau(vigenere_tableau);

            int len_cipher = cipherText.Length;
            int len_key = key.Length;

            //print vigenere_tableau
            /* for (int i = 0; i < 26; i++)
             {
                 for (int j = 0; j < 26; j++)
                 {
                     Console.Write(vigenere_tableau[i, j] + " ");

                 }
                 Console.WriteLine();
             }*/

            string plaint_text = "";
            int c = 0;

            for (int i = 0; i < len_cipher; i++)
            {
                int col_key = 0;

                if (i < len_key)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (vigenere_tableau[0, j] == key[i])
                        {
                            col_key = j;
                            break;
                        }
                    }

                    for (int j = 0; j < 26; j++)
                    {
                        if (vigenere_tableau[j, col_key] == cipherText[i])
                        {
                            plaint_text += vigenere_tableau[j, 0];
                            break;
                        }

                    }
                }

                else
                {
                    for (int j = 0; j < 26; j++)
                    {
                        //repeat plaintext
                        if (vigenere_tableau[0, j] == plaint_text[c])
                        {
                            col_key = j;
                            break;
                        }
                    }
                    c++;

                    for (int j = 0; j < 26; j++)
                    {
                        if (vigenere_tableau[j, col_key] == cipherText[i])
                        {
                            plaint_text += vigenere_tableau[j, 0];
                            break;
                        }

                    }

                }


            }
            // Console.WriteLine("plain text: " + plaint_text);
            return plaint_text;
        }

        public string Encrypt(string plainText, string key)
        {
            //convert to lower case
            plainText = plainText.ToLower();
            key = key.ToLower();
            //table
            char[,] vigenere_tableau = new char[26, 26];
            //do tablueau
            make_Vigenere_tableau(vigenere_tableau);

            int len_plaintext = plainText.Length;
            int len_key = key.Length;
            int diff = len_plaintext - len_key;
            //edit key to auto key
            for (int i = 0; i < diff; i++)
            {
                key += plainText[i % (plainText.Length - 1)];
            }

            //print vigenere_tableau
            /*  for (int i = 0; i < 26; i++)
              {
                  for (int j = 0; j < 26; j++)
                  {
                      Console.Write(vigenere_tableau[i, j] + " ");

                  }
                  Console.WriteLine();
              }*/

            string cipher = "";

            for (int i = 0; i < len_plaintext; i++)
            {
                char c_plain = plainText[i];
                char c_key = key[i];
                int col_key_ind = 0, row_plain_ind = 0;

                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if (c_key == vigenere_tableau[0, k])
                        {
                            col_key_ind = k;
                        }

                        if (c_plain == vigenere_tableau[j, 0])
                        {
                            row_plain_ind = j;
                        }
                    }
                }
                cipher += vigenere_tableau[row_plain_ind, col_key_ind];
            }

            // Console.WriteLine("cipher: " + cipher);
            return cipher;
        }
    }
}