using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
	public class RailFence : ICryptographicTechnique<string, int>
	{


		public int Analyse(string plainText, string cipherText)
		{
			plainText = plainText.ToUpper();
			// throw new NotImplementedException();
			//int fin = 0;
			int count_Analsis = 1;
			int counter = 0;
			while (true)
			{
				for (int j = 0; j < cipherText.Length; j++)
				{
					// check if cipherText has finshed or still are char
					if ((j + 1) * count_Analsis > cipherText.Length)
					{
						break;
					}
					//catch the same char
					if (cipherText[j] == plainText[j * count_Analsis])
					{
						counter++;
					}
					// if next char in cipherText not ecual next char in 
					//plainText break
					else
						break;

				}


				if (counter == (cipherText.Length) / (count_Analsis))
				{
					break;
				}


				else
				{
					count_Analsis++;
					counter = 0;
				}
			}
			return count_Analsis;
		}






		public string Decrypt(string cipherText, int key)
		{
			cipherText = cipherText.ToLower();
			string s_dec = "";
			//throw new NotImplementedException();
			char[,] ch1 = new char[key, cipherText.Length];
			int count = 0;
			decimal len = Math.Ceiling((decimal)cipherText.Length / (decimal)key);
			for (int i = 0; i < key; i++)
			{
				for (int j = 0; j < len; j++)
				{
					if (count < cipherText.Length)
					{
						ch1[i, j] = cipherText[count];
						count++;
					}

				}
			}
			for (int i = 0; i < len; i++)
			{
				for (int j = 0; j < key; j++)
				{
					s_dec += ch1[j, i];
				}
			}
			//cout << s_dec << endl;
			return s_dec;
		}










		public string Encrypt(string plainText, int key)
		{

			//throw new NotImplementedException();
			char[,] ch = new char[key, plainText.Length];
			string s_dec = "";


			decimal len = Math.Ceiling((decimal)plainText.Length / (decimal)key);
			int c = 0;
			//Encription
			for (int i = 0; i < plainText.Length; i++)
			{
				for (int j = 0; j < key; j++)
				{
					if (c < plainText.Length)
					{
						ch[j, i] = plainText[c];
						c++;
					}
					else
						ch[j, i] = '-';
				}
			}

			for (int i = 0; i < key; i++)
			{
				for (int j = 0; j < plainText.Length; j++)
				{
					if (ch[i, j] != '-')
					{
						s_dec += ch[i, j];
					}
				}
			}
			string fin = s_dec.ToUpper();
			//cout << s_enc << endl;
			return fin;
		}
	}
}