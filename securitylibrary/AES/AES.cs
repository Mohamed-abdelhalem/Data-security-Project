using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        int[,] S_box = new int[16, 16] {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
        };

        static int[,] S_box_Inverse = new int[16, 16] {
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };

        int Rcon_ind = 0;
        int[,] Rcon = new int[4, 10] {
            {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};

        int[,] galois_Field_mixMat = new int[4, 4] {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}};

        int[,] galois_Field_Inverse_mixmat = new int[4, 4] {
            {0x0e, 0x0b, 0x0d, 0x09},
            {0x09, 0x0e, 0x0b, 0x0d},
            {0x0d, 0x09, 0x0e, 0x0b},
            {0x0b, 0x0d, 0x09, 0x0e}};

        int[,] key_extra = new int[44, 4];


        //round plaintext
        int[,] round_plain(string plain_text)
        {
            int[,] arr = new int[4, 4];
            int cnt = 2;
            //array 4*4
            //convert to int
            //each index contain 2 index of plaintext
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    arr[j, i] = Convert.ToInt32(("0x" + plain_text[cnt++] + plain_text[cnt++]), 16);
            return arr;
        }

        void add_key_to_arr(string key)
        {
            int[,] key_arr = new int[4, 4];
            //rounded key then add to big array
            key_arr = round_key(key);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    key_extra[i, j] = key_arr[i, j];
        }

        //round key
        int[,] round_key(string key)
        {
            int[,] arr = new int[4, 4];
            int cnt = 2;
            //array 4*4
            //convert to int
            //each index contain 2 index of plaintext
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    arr[i, j] = Convert.ToInt32(("0x" + key[cnt++] + key[cnt++]), 16);
            return arr;
        }
        void key_round_to_start()
        {
            int[] col_3 = new int[4];
            int[] f_col_key = new int[4];
            int[] col_rson = new int[4];
            int[] res = new int[4];
            //last col i=4
            for (int i = 4; i < 44; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //col3
                    col_3[j] = key_extra[i - 1, j];
                    //first col of matrix given key
                    f_col_key[j] = key_extra[i - 4, j];
                    //git col of rson
                    if (Rcon_ind < 10)
                        col_rson[j] = Rcon[j, Rcon_ind];
                }

                //if index 4
                //do rotate col, subsitude and xor
                if (i % 4 == 0)
                {
                    col_3 = Rotate_Col(col_3);
                    col_3 = Substitude_Col(col_3);
                    res = xor(col_3, f_col_key, col_rson, true);
                    Rcon_ind++;
                }
                else
                    res = xor(col_3, f_col_key, col_rson, false);
                //update key
                for (int j = 0; j < 4; j++)
                {
                    key_extra[i, j] = res[j];
                }
            }
        }

        int[] Rotate_Col(int[] col)
        {
            //swap
            int tmp = col[0];
            for (int i = 0; i < 3; i++)
                col[i] = col[i + 1];
            col[3] = tmp;
            return col;
        }
        int[] Substitude_Col(int[] col)
        {
            int[] res = new int[4];
            //index row and col in sbox
            int I_s_box;
            int j_s_box;
            for (int i = 0; i < 4; i++)
            {
                //convert to hexa
                string val = Convert.ToString(col[i], 16);
                if (val.Length == 1)
                {
                    I_s_box = 0;
                    //first ind of string
                    j_s_box = Convert.ToInt32(val[0].ToString(), 16);
                }
                else
                {
                    //search in sbox string of 0 as row and 1 as col
                    I_s_box = Convert.ToInt32(val[0].ToString(), 16);
                    j_s_box = Convert.ToInt32(val[1].ToString(), 16);
                }

                res[i] = S_box[I_s_box, j_s_box];
            }
            return res;
        }

        int[] xor(int[] col, int[] f_col_key, int[] col_rson, bool is_4)
        {
            int[] res = new int[4];
            for (int i = 0; i < 4; i++)
            {
                string val;
                //is 4 xor with 3col else 2col
                if (is_4 == true)
                    val = Convert.ToString(col[i] ^ f_col_key[i] ^ col_rson[i], 16);
                else
                    val = Convert.ToString(col[i] ^ f_col_key[i], 16);

                res[i] = Convert.ToInt32(val, 16);
            }
            return res;
        }

        int[,] initial_round(int[,] round_plain)
        {
            string val;
            int[,] res = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //xor
                    val = Convert.ToString(round_plain[j, i] ^ key_extra[i, j], 16);

                    res[j, i] = Convert.ToInt32(val, 16);
                }
            }
            return res;
        }

        int[,] rounds(int[,] arr, int num_of_round, int num_main_round)
        {
            arr = substitute_matrix_4_4(arr, 0);
            arr = shift_left(arr, 0);
            if (num_main_round == 0)
                arr = mixCols(arr);
            arr = RoundKey(arr, num_of_round);
            return arr;
        }
        int[,] substitute_matrix_4_4(int[,] matrix, int num_of_box)
        {
            int[,] arr = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j], 16);
                    int I_sbox, j_sbox;
                    if (tmp.Length == 1)
                    {
                        I_sbox = 0;
                        j_sbox = Convert.ToInt32(tmp[0].ToString(), 16);
                    }
                    else
                    {
                        I_sbox = Convert.ToInt32(tmp[0].ToString(), 16);
                        j_sbox = Convert.ToInt32(tmp[1].ToString(), 16);
                    }
                    //if 0 is sbox else inverse
                    if (num_of_box == 0)
                        arr[i, j] = S_box[I_sbox, j_sbox];
                    else
                        arr[i, j] = S_box_Inverse[I_sbox, j_sbox];

                }
            }
            return arr;
        }
        int[,] shift_left(int[,] mat, int inverse)
        {
            int[,] arr = new int[4, 4];
            int[] row = new int[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    row[j] = mat[i, j];
                }
                if (inverse == 0)
                    //shift row by ind if row
                    row = shift_Row(row, i);
                else
                    row = shift_Row_Inverse(row, i);
                //store each row shifted
                for (int j = 0; j < 4; j++)
                {
                    arr[i, j] = row[j];
                }
            }
            return arr;
        }
        int[] shift_Row(int[] row, int ind)
        {
            UInt32 num = 0;
            for (int i = 0; i < 3; i++)
            {
                num += Convert.ToUInt32(row[i]);
                num = num << 8;
            }
            num += Convert.ToUInt32(row[3]);

            num = ((num << (ind * 8)) | (num) >> (32 - (ind * 8)));

            int[] newR = new int[4];

            int c = 4;
            while (--c != -1)
            {
                newR[c] = (int)(num & 0xFF);
                num = num >> 8;
            }
            return newR;
        }
        int[,] mixCols(int[,] arrShifted)
        {
            int[] array_Xor = new int[4];
            int[,] mixedCols = new int[4, 4];
            //mul arr*arr
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (galois_Field_mixMat[j, k] == 1)
                        {
                            array_Xor[k] = arrShifted[k, i];
                        }
                        else if (galois_Field_mixMat[j, k] == 2)
                        {
                            array_Xor[k] = multiply_Two(arrShifted[k, i]);
                        }
                        else if (galois_Field_mixMat[j, k] == 3)
                        {
                            array_Xor[k] = multiply_Two(arrShifted[k, i]) ^ arrShifted[k, i];
                        }
                    }
                    //xor res
                    int res = array_Xor[0] ^ array_Xor[1] ^ array_Xor[2] ^ array_Xor[3];
                    mixedCols[j, i] = res;
                }
            }
            return mixedCols;
        }

        int multiply_Two(int x)
        {
            int ret;
            UInt32 temp = Convert.ToUInt32(x << 1);
            ret = (int)(temp & 0xFF);
            if (x > 127)
                ret = Convert.ToInt32(ret ^ 27);
            return ret;
        }
        int[,] RoundKey(int[,] matrix, int Round_index)
        {
            int[,] key_round;
            key_round = get_key(Round_index);
            string tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //xor
                    tmp = Convert.ToString(key_round[i, j] ^ matrix[i, j], 16);
                    key_round[i, j] = Convert.ToInt32(tmp, 16);
                }
            }
            return key_round;
        }

        int[,] get_key(int index_of_round)
        {
            int[,] arr = new int[4, 4];
            int r = 0;
            for (int i = index_of_round * 4; i < index_of_round * 4 + 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    arr[j, r] = key_extra[i, j];
                }
                r++;
            }
            return arr;
        }
        string convirt_Matrix_to_String(int[,] arr)
        {
            StringBuilder str = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    var val = Convert.ToString(arr[j, i], 16);
                    if (val.Length < 2)
                    {
                        str.Append("0" + val);
                    }
                    else str.Append(val);
                }
            }
            return str.ToString().ToUpper().Insert(0, "0x");
        }

        int[,] rounds_decryption(int[,] arr, int num_of_round, int num_dec_round)
        {
            arr = RoundKey(arr, num_of_round);
            //if 0 mix cols
            if (num_dec_round == 0)
            {
                arr = mix_Cols_Inverse(arr);
            }
            arr = shift_left(arr, 1);
            arr = substitute_matrix_4_4(arr, 1);
            return arr;
        }
        int[,] mix_Cols_Inverse(int[,] shifted_matrix)
        {
            int[] array_of_Xor = new int[4];
            int[,] mixedCols = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        int x0 = shifted_matrix[k, i];
                        int x1 = multiply_Two(x0);
                        int x2 = multiply_Two(x1);
                        int x3 = multiply_Two(x2);
                        if (galois_Field_Inverse_mixmat[j, k] == 0x9)
                        {
                            array_of_Xor[k] = x3 ^ x0;
                        }
                        else if (galois_Field_Inverse_mixmat[j, k] == 0xB)
                        {
                            array_of_Xor[k] = x3 ^ x0 ^ x1;
                        }
                        else if (galois_Field_Inverse_mixmat[j, k] == 0xD)
                        {
                            array_of_Xor[k] = x3 ^ x2 ^ x0;

                        }

                        else if (galois_Field_Inverse_mixmat[j, k] == 0xE)
                        {
                            array_of_Xor[k] = x3 ^ x2 ^ x1;
                        }
                    }
                    //xor result
                    int mult = array_of_Xor[0] ^ array_of_Xor[1] ^ array_of_Xor[2] ^ array_of_Xor[3];
                    mixedCols[j, i] = mult;
                }
            }
            return mixedCols;
        }
        int[] shift_Row_Inverse(int[] row, int n)
        {
            UInt32 num = 0;
            for (int i = 0; i < 4; i++)
            {

                num += Convert.ToUInt32(row[i]);
                if (i != 3)
                    num = num << 8;
            }
            num = ((num >> (n * 8)) | (num) << (32 - (n * 8)));

            int[] newR = new int[4];
            int c = 4;
            while (--c != -1)
            {
                newR[c] = (int)(num & 0xFF);
                num = num >> 8;
            }
            return newR;
        }

        int[,] f_Round_Dec(int[,] rounded_cipher)
        {
            rounded_cipher = RoundKey(rounded_cipher, 0);
            return rounded_cipher;
        }

        public override string Decrypt(string cipherText, string key)
        {

            int[,] rounded_cipher = round_plain(cipherText);
            add_key_to_arr(key);
            //schedule key
            key_round_to_start();

            rounded_cipher = rounds_decryption(rounded_cipher, 10, 1);
            int i = 10;
            while (--i != 0)
            {
                rounded_cipher = rounds_decryption(rounded_cipher, i, 0);
            }

            rounded_cipher = f_Round_Dec(rounded_cipher);
            string s = convirt_Matrix_to_String(rounded_cipher);
            return s;
        }

        public override string Encrypt(string plainText, string key)
        {
            int[,] rounded_plain = round_plain(plainText);

            add_key_to_arr(key);
            //schedule key
            key_round_to_start();

            rounded_plain = initial_round(rounded_plain);

            for (int i = 0; i < 9; i++)
                rounded_plain = rounds(rounded_plain, i + 1, 0);

            rounded_plain = rounds(rounded_plain, 10, 1);

            string s = convirt_Matrix_to_String(rounded_plain);
            return s;
        }

    }
}