using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //throw new NotImplementedException();
            char[,] ch1 = new char[105, 105];

            char fist_ch = cipherText[0];
            char second_ch = cipherText[1];

            int c = 0;
            int j = 2;
            int res_of_len = 0;
            int len_of_key = 0;
            // to find length of key
            while (j < 1000)
            {
                for (int k = 0; k < 3; k++)
                {
                    for (int z = 0; z < j; z++)
                    {
                        if (c < plainText.Length)
                        {
                            ch1[k, z] = plainText[c];
                            c++;
                        }
                    }
                }

                //decimal v = Math.Ceiling((decimal)plainText.Length / len_of_key);
                for (int k = 0; k < j; k++)
                {
                    if (ch1[0, k] == fist_ch)
                    {
                        if (ch1[1, k] == second_ch)
                        {
                            res_of_len = 1;
                            break;
                        }

                    }
                }

                if (res_of_len == 1)
                {
                    len_of_key = j;
                    break;
                }
                else
                {
                    c = 0;
                    j++;
                }

            }

            //##################################################
            int counter_result = 1;
            int conter_for_me = 0;
            int[] arr1 = new int[35];
            for (int k = 0; k < len_of_key; k++)
            {
                for (int z = 0; z < cipherText.Length; z++)
                {
                    if (ch1[0, k] != cipherText[z] || ch1[1, k] != cipherText[z + 1] ||
                        ch1[2, k] != cipherText[z + 2])
                    {
                        counter_result++;
                    }
                    else
                    {
                        arr1[conter_for_me] = counter_result;
                        counter_result = 1;
                        conter_for_me++;
                        break;
                    }
                }
            }

            int counter_result_final = 1;
            List<int> List_l = new List<int>();
            int[] final_arry = new int[35];
            for (int m = 0; m < len_of_key; m++)
            {
                for (int mm = 0; mm < len_of_key; mm++)
                {
                    if (arr1[m] > arr1[mm])
                    {
                        counter_result_final++;
                    }
                }
                List_l.Add(counter_result_final);
                //final_arry[m] = counter_result_final;
                counter_result_final = 1;
            }
            return List_l;

        }



        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            //throw new NotImplementedException();
            Dictionary<int, string> dict_dec;
            dict_dec = new Dictionary<int, string>();

            // loop over chipertext
            int count_chiper = 0;


            //2D arry fill in column (ch_dec) matrix 
            char[,] ch_dec = new char[100, 100];

            //max number in list
            int max_number_of_list = key.Max();

            //number of rows (len_f) 
            decimal len_f = Math.Ceiling((decimal)cipherText.Length / (decimal)max_number_of_list);


            // fill ch_dec arry
            for (int i = 0; i < max_number_of_list; i++)
            {
                for (int j = 0; j < len_f; j++)
                {
                    if (count_chiper < cipherText.Length)
                    {
                        ch_dec[j, i] = cipherText[count_chiper];
                        count_chiper++;
                    }
                }
            }




            // temp string put frist virtical char in dictionary as value and key
            string strres_dec = "";
            for (int i = 0; i < max_number_of_list; i++)
            {
                for (int j = 0; j < len_f; j++)
                {
                    strres_dec += ch_dec[j, i];
                }
                dict_dec.Add(i + 1, strres_dec);
                strres_dec = "";
            }




            // empty string to sort chiper according to list<>
            //example if first elment in list = 5 it will loop untill i = 5 
            // put this column in string (strres_dec_fin)
            string strres_dec_fin = "";
            for (int i = 0; i < max_number_of_list; i++)
            {
                foreach (KeyValuePair<int, string> author in dict_dec)
                {
                    if (key.ElementAt(i) == author.Key)
                        strres_dec_fin += author.Value;
                }
            }
            // Console.WriteLine(strres_dec_fin);





            // ch_dec_fin to fill 
            char[,] ch_dec_fin = new char[100, 100];
            int count_resstr_fin = 0;
            for (int i = 0; i < max_number_of_list; i++)
            {
                for (int j = 0; j < len_f; j++)
                {
                    if (count_resstr_fin < strres_dec_fin.Length)
                    {
                        ch_dec_fin[j, i] = strres_dec_fin[count_resstr_fin];
                        count_resstr_fin++;
                    }
                }
            }



            string decription = "";
            for (int i = 0; i < len_f; i++)
            {
                for (int j = 0; j < max_number_of_list; j++)
                {
                    decription += ch_dec_fin[i, j];
                }
            }

            return decription;
            //Console.Write(decription);
        }








        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();

            // key
            Dictionary<int, string> dict;
            dict = new Dictionary<int, string>();

            // 2D arry 
            char[,] ch = new char[100, 100];

            // resstr chiper text
            string str1 = "", resstr = "";


            int mx = key.Max();

            decimal len_f = Math.Ceiling((decimal)plainText.Length / (decimal)mx);
            //Console.WriteLine(len_f);

            int counter = 0;

            // fill in rows
            for (int i = 0; i < len_f; i++)
            {
                for (int j = 0; j < mx; j++)
                {
                    // fill the matrix with 'x' in empty places
                    if (counter < plainText.Length)
                    {
                        ch[i, j] = plainText[counter];
                        counter++;
                    }
                    else
                        ch[i, j] = 'x';
                }
            }



            for (int i = 0; i < mx; i++)
            {
                for (int j = 0; j < len_f; j++)
                {
                    str1 += ch[j, i];
                }
                //Console.WriteLine(str1);

                dict.Add(key.ElementAt(i), str1);

                str1 = "";
            }

            // foreach to sort key
            foreach (KeyValuePair<int, string> author in dict.OrderBy(x => x.Key))
            {
                Console.WriteLine("Key: {0}, Value: {1}",
                    author.Key, author.Value);
                resstr += author.Value;
            }

            // Console.WriteLine(resstr);
            return resstr;
        }
    }
}