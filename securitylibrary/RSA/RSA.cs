using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            
            var n = p * q;
            int c = 1;
            for (int i = 1; i <= e; i++)
                c = (c * M) % n;
            c %= n;
            return c;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            
            var n = p * q;
            var phiN = (p - 1) * (q - 1);
            AES.ExtendedEuclid ex = new AES.ExtendedEuclid();
            var d = ex.GetMultiplicativeInverse(e, phiN);
            int m = 1;
            for (int i = 1; i <= d; i++)
                m = (m * C) % n;
            m %= n;
            return m;
        }
    }
}
