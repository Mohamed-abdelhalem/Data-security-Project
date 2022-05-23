using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            char[,] arr = new char[5, 5];
            string alpha = "abcdefghiklmnopqrstuvwxyz",
                   plainText = "";
            //convert to lower case
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            //if key or cipher text contain j convert it to i
            if (key.Contains("j"))
            {
                key = key.Replace("j", "i");
            }
            if (cipherText.Contains("j"))
            {
                cipherText = cipherText.Replace("j", "i");
            }

            //concat key + alpha
            key += alpha;
            //remove duplicated
            string distinct = new String(key.Distinct().ToArray());
            //fill arr 5*5
            int l = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arr[i, j] = distinct[l];
                    l++;
                }
            }

            //print arr 5*5

            /*   for (int i = 0; i < 5; i++)
               {
                   for (int j = 0; j < 5; j++)
                   {
                       Console.Write(arr[i, j] + " ");
                   }
                   Console.WriteLine("");
               }
            */

            // row col row col
            int[] active = new int[4];

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                //search row col index
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (arr[j, k] == cipherText[i])
                        {
                            active[0] = j;
                            active[1] = k;
                        }
                        else if (arr[j, k] == cipherText[i + 1])
                        {
                            active[2] = j;
                            active[3] = k;
                        }
                    }
                }

                if (active[0] == active[2]) //same row
                {
                    int a1 = active[1] - 1;
                    if (a1 < 0)
                        a1 = 4;
                    int a3 = active[3] - 1;
                    if (a3 < 0)
                        a3 = 4;
                    plainText += Convert.ToString(arr[active[0], a1 % 5]); //same row , col-1 % 5
                    plainText += Convert.ToString(arr[active[0], a3 % 5]);
                }
                else if (active[1] == active[3])//same col
                {
                    int a0 = active[0] - 1;
                    if (a0 < 0)
                        a0 = 4;
                    int a2 = active[2] - 1;
                    if (a2 < 0)
                        a2 = 4;
                    plainText += Convert.ToString(arr[a0 % 5, active[1]]); //row-1 %5 , same col
                    plainText += Convert.ToString(arr[a2 % 5, active[1]]);
                }
                else
                {
                    plainText += Convert.ToString(arr[active[0], active[3]]); //same row inverse col
                    plainText += Convert.ToString(arr[active[2], active[1]]); //same row inverse col
                }
            }

            //if two char equal and between x remove it
            for (int i = 0; i < plainText.Length - 2; i += 2)
            {
                if (plainText[i + 1] == 'x' && plainText[i] == plainText[i + 2])
                {
                    plainText = plainText.Remove(i + 1, 1);
                    i--;
                }
            }


            //if last char x remove it
            if (plainText[plainText.Length - 1] == 'x')
                plainText = plainText.Remove(plainText.Length - 1);
            // Console.WriteLine(cipherText);
            // Console.WriteLine(plainText);
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            //array 5*5
            char[,] arr = new char[5, 5];
            string new_plainText = "",
                   alpha = "abcdefghiklmnopqrstuvwxyz",
                   cipher = "";
            //convert to lower case
            key = key.ToLower();
            plainText = plainText.ToLower();

            /*
              if (key.Contains("j") && key.Contains("i"))
                    {
                        int ind1 = key.IndexOf("i");
                        int ind2 = key.IndexOf("j");
                        Console.WriteLine(ind1);
                        Console.WriteLine(ind2);

                        if (ind1 > ind2)
                            key = key.Remove(ind1, 1);
                        else
                            key = key.Remove(ind2, 1);
                    }
                */

            //if key or plain text contain j convert it to i
            if (key.Contains("j"))
            {
                key = key.Replace("j", "i");
            }
            if (plainText.Contains("j"))
            {
                plainText = plainText.Replace("j", "i");
            }

            //concat key + alpha
            key += alpha;

            //remove duplicated
            string distinct = new String(key.Distinct().ToArray());

            //fill arr 5*5
            int len = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    arr[i, j] = distinct[len];
                    len++;
                }
            }

            //print arr 5*5

            /*  for (int i = 0; i < 5; i++)
              {
                  for (int j = 0; j < 5; j++)
                  {
                      Console.Write(arr[i, j] + " ");
                  }
                  Console.WriteLine("");
              }
            */


            //edit plaintext
            int iteration = 0;
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                char c1 = Convert.ToChar(plainText[i]);
                char c2 = Convert.ToChar(plainText[i + 1]);
                if (c1 == c2)
                {
                    new_plainText += plainText[i];
                    new_plainText += 'x';
                    // p += plainText[i + 1];
                    i--;
                    iteration++;
                }
                else
                {
                    new_plainText += plainText[i];
                    new_plainText += plainText[i + 1];
                }


            }

            if (iteration + plainText.Length != new_plainText.Length)
                new_plainText += plainText[plainText.Length - 1];

            if (new_plainText.Length % 2 != 0)
            {
                new_plainText += "x";
            }

            // row col row col
            int[] active = new int[4];
            for (int i = 0; i < new_plainText.Length; i += 2)
            {
                //search row col index
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (arr[j, k] == new_plainText[i])
                        {
                            active[0] = j;
                            active[1] = k;
                        }
                        else if (arr[j, k] == new_plainText[i + 1])
                        {
                            active[2] = j;
                            active[3] = k;
                        }
                    }
                }

                if (active[0] == active[2]) //same row
                {
                    cipher += Convert.ToString(arr[active[0], (active[1] + 1) % 5]); //same row , col+1 % 5
                    cipher += Convert.ToString(arr[active[0], (active[3] + 1) % 5]);
                }
                else if (active[1] == active[3])
                {
                    cipher += Convert.ToString(arr[(active[0] + 1) % 5, active[1]]); //row+1 %5 , same col
                    cipher += Convert.ToString(arr[(active[2] + 1) % 5, active[1]]);
                }
                else
                {
                    cipher += Convert.ToString(arr[active[0], active[3]]); //same row inverse col
                    cipher += Convert.ToString(arr[active[2], active[1]]); //same row inverse col
                }
            }

            return cipher;
        }
    }
}
