#pragma warning(push)
#pragma warning(disable: 4244 4267)
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <netnode.hpp>
#pragma warning(pop)

#include <windows.h>

#include "Scanner.h"

char IDAP_comment[] = "SigMe";
char IDAP_help[] = "SigMe";
char IDAP_name[] = "SigMe";
char IDAP_hotkey[] = "Ctrl-Alt-Shift-S";

bool idaapi IDAP_run(size_t arg);
void idaapi IDAP_term(void);
int idaapi IDAP_init(void);

static plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,
	IDAP_init, IDAP_term, IDAP_run, IDAP_comment, IDAP_help, IDAP_name, IDAP_hotkey
};

char *g_SelectionDialog =
"STARTITEM 0\n"
"SigMe\n\n"
"Select your preferred signature format:\n"
"<##Signature Format##IDA Byte Array:R>\n"
"<C Array w/ Mask:R>\n"
"<SourceMod Pattern:R>\n"
"<Byte Pattern w/ Custom Wildcard:R>>\n"
"<#No leading 0x#Custom Wildcard Byte:M:2:2::>\n"
"SigMe will generate sequentially unique\n"
"signatures by default. If the signature\n"
"matching algorithm you employ does not\n"
"work sequentially then tick the box.\n"
"<##Additional Options##Generate Unique Signature:C>\n"
"<Copy to Clipboard:C>>\n";

template<typename T>
T GetNetnodeValue(const char* p_Name, T p_DefaultVal)
{
	T s_Value;
	netnode s_Node(p_Name, 0, true);

	if (s_Node.valobj(&s_Value, sizeof(T)) != sizeof(T))
		return p_DefaultVal;

	return s_Value;
}

template<typename T>
void SetNetnodeValue(const char* p_Name, T p_Value)
{
	netnode s_Node(p_Name, 0, true);
	s_Node.set(&p_Value, sizeof(T));
}

bool idaapi IDAP_run(size_t arg)
{
	PLUGIN.flags |= PLUGIN_UNL;

	// Load our saved settings (if any).
	uval_t s_WildcardByte = GetNetnodeValue<uint8_t>("$ sigme_wb", 0xDD);
	ushort s_SelectedMethod = GetNetnodeValue<uint8_t>("$ sigme_sm", 0);
	ushort s_CheckMask = GetNetnodeValue<uint8_t>("$ sigme_cm", 2);

	// Show our main form.
	if (ask_form(g_SelectionDialog, &s_SelectedMethod, &s_WildcardByte, &s_CheckMask) != 1)
		return false;

	// Store the new setting values in the IDB.
	SetNetnodeValue<uint8_t>("$ sigme_wb", (uint8_t) s_WildcardByte);
	SetNetnodeValue<uint8_t>("$ sigme_sm", (uint8_t) s_SelectedMethod);
	SetNetnodeValue<uint8_t>("$ sigme_cm", (uint8_t) s_CheckMask);

	bool s_Unique = (s_CheckMask & 1) != 0;
	bool s_Clipboard = (s_CheckMask & 2) != 0;

	msg("[SigMe] Creating signature. Please wait...\n");

	// Initiate our Scanner and start scanning.
	Scanner s_Scanner(get_screen_ea(), s_Unique);
	s_Scanner.StartScanning();

	// Did we encounter an error?
	if (s_Scanner.HasError())
	{
		msg("[SigMe] Signature creation failed.\n");
		return false;
	}

	// If not, print the final signature.
	std::string s_Signature = s_Scanner.GetSignature((Scanner::SigType) s_SelectedMethod);
	msg("[SigMe] Generated signature (%d bytes):\n%s\n", s_Scanner.GetSignatureLength(), s_Signature.c_str());

	// Copy to clipboard.
	if (s_Clipboard)
	{
		if (OpenClipboard(nullptr))
		{
			EmptyClipboard();

			HGLOBAL s_ClipboardBlob = GlobalAlloc(GMEM_MOVEABLE, s_Signature.size() + 1);
			strcpy_s(reinterpret_cast<char*>(GlobalLock(s_ClipboardBlob)), s_Signature.size() + 1, s_Signature.c_str());
			GlobalUnlock(s_ClipboardBlob);

			if (SetClipboardData(CF_TEXT, s_ClipboardBlob) == NULL)
				GlobalFree(s_ClipboardBlob);

			CloseClipboard();
		}
	}

	return true;
}

void idaapi IDAP_term(void)
{
	return;
}

int idaapi IDAP_init(void)
{
	return PLUGIN_KEEP;
}