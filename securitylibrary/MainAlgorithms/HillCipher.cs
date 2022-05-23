using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {




        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            List<double> C = cipherText.ConvertAll(x => (double)x);
            List<double> P = plainText.ConvertAll(x => (double)x);
            int Csqrt = Convert.ToInt32(Math.Sqrt((C.Count)));
            Matrix<double> CMatrix = DenseMatrix.OfColumnMajor(Csqrt, (int)cipherText.Count / Csqrt, C.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(Csqrt, (int)plainText.Count / Csqrt, P.AsEnumerable());
            List<int> Key = new List<int>();
            int a = 0;
            while(a < 26)
            {
                int b = 0;
                while( b < 26)
                {
                    int c = 0;
                    while(c < 26)
                    {
                        int d = 0;
                        while(d < 26)
                        {
                            Key = new List<int>(new[] { a, b, c, d });
                            List<int> resOFenc = Encrypt(plainText, Key);
                            if (resOFenc.SequenceEqual(cipherText))
                            {
                                return Key;
                            }
                            d++;
                        }
                        c++;
                    }
                    b++;
                }
                a++;
            }

            throw new InvalidAnlysisException();

        }


        public string Analyse(string plainText, string cipherText)
        {
             throw new NotImplementedException();
        }
        public Matrix<double> ModCof(Matrix<double> Matrix, int A)
        {
            Matrix<double> resultMat = DenseMatrix.Create(3, 3, 0.0);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int x = i, y = j , x1 = i , y1 = j;
                    if (x == 0)
                    {        x = 1;    }
                    else
                    {        x = 0;    }
                    if (y == 0)
                    {        y = 1;    }
                    else
                    {        y = 0;    }
                    if (x1 == 2)
                    {        x1 = 1;   }
                    else
                    {        x1 = 2;   }
                    if (y1 == 2)
                    {        y1 = 1;   }
                    else
                    {        y1 = 2;   }

                    double result = ( (Matrix[x, y] * Matrix[x1, y1] - Matrix[x, y1] * Matrix[x1, y]) * Math.Pow(-1, i + j) * A ) % 26;
                    resultMat[i, j] = result;
                    if (resultMat[i, j] >= 0)
                    {
                        resultMat[i, j] = result;
                    }
                    else
                    {
                        resultMat[i, j] = result + 26;
                    }
                }
            }
            return resultMat;
        }
        /*       0  1  2           0  1  2            0  1  2
           0   | 00 -- --|   0   | -- 01 --|    0   | -- -- 02|
           1   | -- 11 12|   1   | 10 -- 12|    1   | 10 11 --|
           2   | -- 21 22|   2   | 20 -- 22|    2   | 20 21 --|
        */
        /* rule of signs
         * + - + 
         * - + - 
         * + - +
         */
        public int det(Matrix<double> M)
        {
            double A = M[0, 0] * (M[1, 1] * M[2, 2] - M[1, 2] * M[2, 1]) -
                       M[0, 1] * (M[1, 0] * M[2, 2] - M[1, 2] * M[2, 0]) +
                       M[0, 2] * (M[1, 0] * M[2, 1] - M[1, 1] * M[2, 0]);
            int AI = (int)A % 26;
            if (AI >= 0)
            {
                AI = (int)A % 26;
            }
            else
            {
                AI = (int)A % 26 + 26;
            }
            for (int i = 0; i < 26; i++)
            {
                if (AI * i % 26 == 1)
                {
                    return i;
                }
            }
            return -1;
        }   
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            List<double> k = key.ConvertAll(x => (double)x);
            List<double> C = cipherText.ConvertAll(x => (double)x);
            int resSqrt = Convert.ToInt32(Math.Sqrt((key.Count)));
            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(resSqrt, (int)key.Count / resSqrt, k.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(resSqrt, (int)cipherText.Count / resSqrt, C.AsEnumerable());
            List<int> finalRes = new List<int>();
            if (keyMatrix.ColumnCount == 3)
            {
                keyMatrix = ModCof(keyMatrix.Transpose(), det(keyMatrix));
            }
            else
            {
                keyMatrix = keyMatrix.Inverse();
            }
            if (Math.Abs((int)keyMatrix[0, 0]).ToString() != Math.Abs((double)keyMatrix[0, 0]).ToString())
            {
                throw new SystemException();
            }
            for (int i = 0; i < PMatrix.ColumnCount; i++)
            {
                List<double> Res = new List<double>();
                Res = ((((PMatrix.Column(i)).ToRowMatrix() * keyMatrix) % 26).Enumerate().ToList());
                for (int j = 0; j < Res.Count; j++)
                {
                    int x = (int)Res[j];
                        if(x >= 0)
                                 {
                                      x= (int)Res[j];
                                 }
                         else
                                 {

                                       x=  (int)Res[j] + 26;
                                 }
                    finalRes.Add(x);
                }
            }
            return finalRes;
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
        /* plain      [15 24 14 4  14 4
                       0  12 17 12 13 24 ]  */
        /* key        [3 2
         *             8 5] 
          */
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> c = new List<int>();
            if ( key.Count() == 4)
            {
                for(int i = 0; i < plainText.Count(); i+=2)
                {
                    for (int j = 0; j < key.Count(); j += 2)
                    {
                        int cipher = ( (key[j] * plainText[i]) + (key[j + 1] * plainText[i + 1]) ) % 26;
                        c.Add(cipher);
                    }
                }
            }
            if (key.Count() == 9)
            {
                for (int i = 0; i < plainText.Count(); i += 3)
                {
                    for (int j = 0; j < key.Count(); j += 3)
                    {
                        int cipher = ((key[j] * plainText[i]) + (key[j + 1] * plainText[i + 1]) + (key[j + 2] * plainText[i + 2])) % 26;
                        c.Add(cipher);
                    }
                }
            }
            return c;
        }
        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            List<double> C = cipher3.ConvertAll(x => (double)x);
            List<double> P = plain3.ConvertAll(x => (double)x);
            int resSqrt = Convert.ToInt32(Math.Sqrt((C.Count)));
            Matrix<double> CMatrix = DenseMatrix.OfColumnMajor(resSqrt, (int)cipher3.Count / resSqrt, C.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(resSqrt, (int)plain3.Count / resSqrt, P.AsEnumerable());
            List<int> Key = new List<int>();
            Matrix<double> KMatrix = DenseMatrix.Create(3, 3, 0);
            PMatrix = ModCof(PMatrix.Transpose(), det(PMatrix));
            KMatrix = (CMatrix * PMatrix);
            Key = KMatrix.Transpose().Enumerate().ToList().Select(i => (int)i % 26).ToList();
            return Key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();

        }


       }
     
    }
     

