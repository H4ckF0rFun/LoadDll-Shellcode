#include <Windows.h>

extern "C" __declspec(dllexport) 
void TestFunc(){
	MessageBox(0, TEXT("This is test func"), TEXT("Tips"), MB_OK);
}