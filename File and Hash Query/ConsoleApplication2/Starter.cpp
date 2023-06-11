#include "alper.h"
#include <iostream>
#include <fstream>  // For working with files
#include <iomanip>  // For output formatting
#include <openssl/evp.h>  // For cryptographic hash functions
#include <sqlite3.h>
#include <stdio.h>
#include <string>
#include <sstream>

int main()
{
	std::string name;
	std::cout << "Hash'ini bulmak istediginiz dosyanin dosya-yolunu giriniz: ";
	getline(std::cin, name);
	const char* filename = name.c_str();

	//const char* filename = "C:\\Test\\output.txt";

	std::ifstream file(filename);

	if (file.good()) {
		std::string a = alper(filename);
		//std::cout << a;
	}
	else {
		std::cout << "Boyle bir dosya bulunamadi!" << std::endl;
	}	
	return 0;
}