#pragma once
#include "stdafx.h"

using namespace std;

void extended_euclid(LINT a, LINT b, LINT *x, LINT *y, LINT *d);
void Vinere(LINT E, LINT N, LINT *D, int *key_index);
void Vulnerable_Generator(LINT p, LINT q, LINT *E, LINT *N, LINT *origin_D);

/*
Function extended_euclid

	This function calculates coefficients a, b and GCD(a,b)
	in comparison a*x+b*y=GCD(a,b)
	The answer is stored three LINT: x,y,d

Arguments:
IN:
	a - the first coefficient in comparison
	b - the second coefficient in comparison
OUT:
	x - the first variable in comparison
	y - the second variable in comparison
	d - greatest common divisor of a and b

Return value:
	None
*/

void extended_euclid(
	__in	LINT a,
	__in	LINT b,
	__out	LINT *x,
	__out	LINT *y,
	__out	LINT *d)


	/* calculates a * *x + b * *y = gcd(a, b) = *d */

{

	LINT q, r, x1, x2, y1, y2;
	if (b == 0)
	{
		*d = a, *x = 1, *y = 0;
		return;
	}
	x2 = 1, x1 = 0, y2 = 0, y1 = 1;

	while (b > 0)
	{
		q = a / b, r = a - q * b;
		*x = x2 - q * x1, *y = y2 - q * y1;
		a = b, b = r;
		x2 = x1, x1 = *x, y2 = y1, y1 = *y;
	}
	*d = a, *x = x2, *y = y2;
}

/*
Function Vinere

	This function calculates the private part of key
	with using open part of key (E,N)
	The answer is the private part of key D

Arguments:
IN:
	E - the first part of public key
	N - the second part of public key
OUT:
	D - the part of private key

Return value:
	None
*/

void Vinere(
	__in LINT E,
	__in LINT N,
	__out LINT *D,
	__out int *key_index)
{
	vector<LINT> V;
	vector<LINT> H;
	vector<LINT> Z;

	H.push_back(E);
	Z.push_back(N);
	vector<LINT> potential_D;
	LINT limitD = root(root(N / 3)) - 1;

	LINT M = "10010101001011111";
	LINT LC = mexp(M, E, N);

	for (unsigned int i = 0;; i++)
	{
		if (Z[i] == 0) { break; }
		else
		{
			V.push_back(H[i] / Z[i]);
			Z.push_back(H[i] - Z[i] * V[i]);
			H.push_back(Z[i]);
		}
		if (i == 0)
			potential_D.push_back(1);
		else if (i == 1)
			potential_D.push_back(V[i]);
		else
		{
			if ((V[i]) == 0) break;
			potential_D.push_back(potential_D[i - 1] * V[i] + potential_D[i - 2]);

		}

		LINT M2 = mexp(LC, potential_D[i], N);

		if (M == M2)
		{
			*D = potential_D[i];
			*key_index = i;
			cout << "Key found index " << i << endl;
			return;
		}

		if (potential_D[i] > limitD)
		{
			(*D) = KEY_NOT_FOUND;
			cout << "Key not found" << endl;
			return;
		}
	}
	cout << "ERROR!! Left endless loop!!!" << endl;
	return;
}

/*
Function Vulnerable_Generator

	This function recieves public part of key from
	couple p,q
	The answer is the public part of key E,N

Arguments:

IN:
	p - first prime
	q - second prime
OUT:
	*E - the first part of public key
	*N - the second part of public key
	*origin_D - private key

Return value:
	None
*/

void Vulnerable_Generator(
	__in  LINT p,
	__in  LINT q,
	__out LINT *E,
	__out LINT *N,
	__out LINT *origin_D)
{
	LINT NOD;
	LINT koef;

	*N = mul(p, q);
	LINT eiler_func = mul((p - 1), (q - 1));
	LINT limitD = root(root((*N) / 3)) - 1;
	for (; limitD > 0; limitD--)
	{
		extended_euclid(limitD, eiler_func, E, &koef, &NOD); // E - output

		LINT one = LINT(1);

		if ((*E < *N) && (NOD == 1) && (gcd(*E, eiler_func) == 1) && ((*E) != one))
		{
#ifdef DBG_PRINT
			cout << endl << "Eiler: " << eiler_func.decstr() << endl;
			cout << "Finished generating E, D and N." << endl;
			cout << "E is " << (*E).decstr() << endl;
			cout << "D is " << limitD.decstr() << endl;
			cout << "N is " << (*N).decstr() << endl;
			cout << "p is " << p.decstr() << endl;
			cout << "q is " << q.decstr() << endl;
#endif
			*origin_D = limitD;
			return;
		}
	}

	cout << "Couldn't generate public key" << endl;
	return;
}

/*
Produces two random prime numbers
by generating random number and taking
next nearest prime one

Arguments:
IN:
	length - the number of bits in result prime numbers
OUT:
	P - first number
	Q - second number

Return value:
	None
*/
void Prime_Number_Generator(
	__in int length,
	__out LINT *P,
	__out LINT *Q)
{
	*P = nextprime(randl(length) + 1, 1);
#ifdef DBG_PRINT
	cout << "The P is " << (*P).decstr() << endl;
#endif
	*Q = nextprime(randl(length) + 1, 1);
#ifdef DBG_PRINT
	cout << "The Q is " << (*Q).decstr() << endl;
#endif
}

void Generalized_Wiener_Attack(
	__in LINT E,
	__in LINT N,
	__out LINT *p,
	__out LINT *q
	)
{
	vector<LINT> P;
	vector<LINT> V;
	vector<LINT> H;
	vector<LINT> Z;

	H.push_back(E);
	Z.push_back(N);
	vector<LINT> potential_D;
	vector<LINT> potential_K;
	LINT limitD = root(root(N / 3)) - 1;

	LINT M = "10010101001011111";
	LINT LC = mexp(M, E, N);

	for (unsigned int i = 0;; i++)
	{
		if (Z[i] == 0) { break; }
		else
		{
			V.push_back(H[i] / Z[i]);
			Z.push_back(H[i] - Z[i] * V[i]);
			H.push_back(Z[i]);
		}
		if (i == 0)
		{
			potential_D.push_back(1);
			potential_K.push_back(V[i]);
		}
		else if (i == 1)
		{
			potential_D.push_back(V[i]);
			potential_K.push_back(V[i - 1] * V[i] + 1);
		}
		else
		{
			if ((V[i]) == 0) break;
			potential_D.push_back(potential_D[i - 1] * V[i] + potential_D[i - 2]);
			potential_K.push_back(potential_K[i - 1] * V[i] + potential_K[i - 2]);

		}

		LINT M2 = mexp(LC, potential_D[i], N);

		if (M == M2)
		{
			LINT s;
			LINT t;
			LINT p_wave;
			LINT temp_N;
			LINT potential_P;
			temp_N = N.sqr();
			temp_N = temp_N.sqr();

			s = N + 1 - (E*potential_D[i]) / potential_K[i];
			t = (s*s - 4 * N);
			t = t.sqr();
			p_wave = (s + t) / 2;
			for (int k = -3; k < 3; k++)
			{
				potential_P = p_wave + (2 * k + 1)*temp_N;

				//Coppersmith algorithm
				//

				cout << "Result q: " << (N / potential_P).decstr() << endl;
			}

			cout << "E: " << E.decstr();
			cout << " N: " << N.decstr();
			for (unsigned int count = 0; count < i; count++)
			{
				cout << "Numerator : " << potential_K[count].decstr() << endl;
				cout << "Divisor : " << potential_D[count].decstr() << endl;
			}

			cout << "Key found index " << i << endl;
			return;
		}

		if (potential_D[i] > limitD)
		{
			*p = KEY_NOT_FOUND;
			*q = KEY_NOT_FOUND;
			cout << "E: " << E.decstr();
			cout << " N: " << N.decstr();
			for (unsigned int count = 0; count < i; count++)
			{
				cout << "Numerator : " << potential_K[count].decstr() << endl;
				cout << "Divisor : " << potential_D[count].decstr() << endl;
			}
			cout << "Key not found" << endl;
			return;
		}
	}
	cout << "ERROR!! Left endless loop!!!" << endl;
	return;
};

int _tmain(int argc, _TCHAR* argv[])
{
	vector <LINT> primes_vector;
	LINT E;
	LINT N;
	LINT D;
	LINT P;
	LINT Q;
	LINT origin_D;
	int key_index = 0;

#ifdef KEY_TXT_PRINT
	ofstream FILE;
	string rez = "";
	FILE.open("key for debug.txt");
#endif

	while (1 == 1)
	{
		char choice;

		cout << "\nPlease, choose what option you want:\n";
		cout << "1 - Generate vulnerable keys with specified length and break them\n";
		cout << "2 - Input prepared keys from file keys.txt and test them for being vulnerable\n";
		cout << "3 - Exit\n";

		scanf(" %c", &choice);

		switch (choice) {
		case '1':
		{
					vector<int> keys = {9};// 64, 128, 256, 512, 1024, 2048 /*4096*/ };

					for (unsigned int counter = 0; counter < keys.size(); counter++)
					{
						Prime_Number_Generator(keys[counter], &P, &Q);
						Vulnerable_Generator(P, Q, &E, &N, &origin_D);

#ifdef DBG_PRINT
						cout << "Starting Vinere attack with E: " << E.decstr();
						cout << " and N: " << N.decstr() << endl;
#endif
						int time = GetTickCount();
						Vinere(E, N, &D, &key_index);
						LINT p;
						LINT q;
						Generalized_Wiener_Attack(E, N, &p, &q);
#ifdef DBG_PRINT
						cout << "The key is: " << D.decstr() << endl;
#endif
						if (origin_D == D)
							cout << "For key length " << keys[counter] << " Vinere succedeed in " << GetTickCount() - time << " ticks" << endl << "The key was " << key_index << " in the divisors array of corvengets" << endl;

#ifdef KEY_TXT_PRINT				
						rez += E.decstr();
						rez += "\n";
						rez += N.decstr();
						rez += "\n";
						rez += D.decstr();
						rez += "\n\n";
						FILE << rez;
#endif
					}

#ifdef KEY_TXT_PRINT
					FILE.close();
#endif
		}
			break;
		case '2':
		{
					string line_E;
					string line_N;
					ifstream myfile("keys.txt");
					LINT lint_E;
					LINT lint_N;
					LINT output_D;

					if (!myfile.is_open())
					{
						cout << "Couldn't open file, error." << endl;
						goto clean0;
					}

					while (!myfile.eof())
					{
						getline(myfile, line_E);
						lint_E = LINT(line_E.c_str());
						getline(myfile, line_N);
						lint_N = LINT(line_N.c_str());

						// For one-string keys with equal E and N length
						//length = line.length();
						//string str_E = line.substr(0, length/2);
						//string str_N = line.substr(length / 2, length / 2);
						//lint_E = LINT(str_E.c_str());
						//lint_N = LINT(str_N.c_str());
#ifdef DBG_PRINT
						cout << "Starting Vinere attack with E: " << lint_E.decstr();
						cout << " and N: " << lint_N.decstr() << endl;
#endif
						int time = GetTickCount();
						Vinere(lint_E, lint_N, &output_D, &key_index);
						if (output_D != KEY_NOT_FOUND)
						{
							cout << "The key is: " << output_D.decstr() << endl;
							cout << "For key length " << (line_E.length() + line_N.length()) << " Vinere succedeed in " << GetTickCount() - time << " ticks" << endl << "The key was " << key_index << " in the divisors array of corvengets" << endl;
						}
						else
						{
							cout << "The key is not vulnerable to Vinere attack. Moving to next key." << endl;
						}
					}
		}
			break;
		case '3':
		{
					goto clean0;
		}
			break;
		default:
			cout << "Invalid choice specified. Re-enter your choice" << endl;
		}
	}

clean0:
	return 0;
}