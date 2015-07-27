#pragma once
#include "main.h"

using namespace std;

ERROR_CODE Generalized_Wiener_Attack(
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

//Continued fraction
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
//Found private key
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
			return SUCCESS;
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
			return FAIL;
		}
	}
	return LEFT_ENDLESS_LOOP;
};

int _tmain(int argc, _TCHAR* argv[])
{
	ERROR_CODE status = UNINITIALIZED;
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
					vector<int> keys = {32};// 64, 128, 256, 512, 1024, 2048 /*4096*/ };

					for (unsigned int counter = 0; counter < keys.size(); counter++)
					{
						status = Prime_Number_Generator(keys[counter], &P, &Q);
						if (status != SUCCESS)
							_CrtDbgBreak();
						status = Vulnerable_Generator(P, Q, &E, &N, &origin_D);
						if (status != SUCCESS)
							_CrtDbgBreak();

#ifdef DBG_PRINT
						cout << "Starting Vinere attack with:\nE: " << E.decstr();
						cout << "\nN: " << N.decstr() << endl;
						cout << "\nD: " << origin_D.decstr();
#endif
						int time = GetTickCount();
						LINT p;
						LINT q;
						status = Generalized_Wiener_Attack(E, N, &p, &q);
						if (status != SUCCESS)
							_CrtDbgBreak();
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
						LINT p;
						LINT q;
						Generalized_Wiener_Attack(lint_E, lint_N, &p, &q);
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