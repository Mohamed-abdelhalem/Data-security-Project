using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int A1 = 1, A2 = 0, A3 = baseN, B1 = 0, B2 = 1, B3 = number;
            //loop to fill the values of the table 
            do
            {
                int q = A3 / B3, FIRST_VARIABLE_1 = A1 - (q * B1), SECOND_VARIABLE_2 = A2 - (q * B2), THIRD_VARIABLE_3 = A3 - (q * B3);
                A1 = B1; A2 = B2; A3 = B3; B1 = FIRST_VARIABLE_1; B2 = SECOND_VARIABLE_2; B3 = THIRD_VARIABLE_3;
            } while (B3 != 1 && B3 != 0);// condition to break the loob 

            // checking the value of B3 to determine if there is a multiplicativeinverse or not
            if (B3 == 1) { if (B2 < -1) { B2 = B2 + baseN; } return B2; }
            return -1;
        }
    }
}

