#include "Conversions.h"
#include <shlwapi.h>

std::string Conversion::vectorToString(std::vector<std::string>(input))
{
	std::string result;

	for (const auto& index : input)
	{
		result += index;
	}

	return result;
}

std::string Conversion::wcharToString(wchar_t input[1024])
{
	std::wstring wstringValue(input);
	std::string convertedString(wstringValue.begin(), wstringValue.end());

	return convertedString;
}

std::string Conversion::base64Encode(std::string dataRequest)
{
	std::string b64Data = base64_encode(reinterpret_cast<const unsigned char*>(dataRequest.c_str()), dataRequest.length());

	return b64Data;
}

wchar_t* Conversion::charArrayToLPCWSTR(char* charArray)
{
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

wchar_t* Conversion::charToWChar(const char* text)
{
	const size_t size = strlen(text) + 1;
	wchar_t* wText = new wchar_t[size];

	mbstowcs(wText, text, size);
	return wText;
}
