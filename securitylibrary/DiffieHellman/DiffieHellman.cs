using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            var Ya = power(alpha, xa, q); //alpha^Xa mod q
            var Yb = power(alpha, xb, q);
            var K1 = power(Yb, xa, q);
            var K2 = power(Ya, xb, q);

            List<int> K = new List<int>();
            K.Add(K1);
            K.Add(K2);

            return K;
        }
        public int power(int alpha_OR_Y, int X, int q)
        {
            int r = 1;
            for (int i = 1; i <= X; i++)
            {
                r = (r * alpha_OR_Y) % q;
            }
            return r;
        }
    }
}
