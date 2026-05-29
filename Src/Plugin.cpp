#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4244 4267)
#endif
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <netnode.hpp>
#include <kernwin.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#include "Scanner.h"
#include "SymbolPatterns.h"

static const char IDAP_comment[] = "SigMe";
static const char IDAP_help[]    = "SigMe";
static const char IDAP_name[]    = "SigMe";
static const char IDAP_hotkey[]  = "Ctrl-Alt-Shift-S";

static bool idaapi IDAP_run(size_t arg);
static void idaapi IDAP_term(void);
static plugmod_t* idaapi IDAP_init(void);

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,
	IDAP_init,
	IDAP_term,
	IDAP_run,
	IDAP_comment,
	IDAP_help,
	IDAP_name,
	IDAP_hotkey
};

static const char g_SelectionDialog[] =
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
"<Copy to Clipboard:C>>\n"
"\n"
"Bulk symbol pattern tools:\n"
"<#Export an IDA pattern for every user-renamed symbol (functions + globals) to a file#Export Renamed Symbols...:B:0:::>\n"
"<#Load a pattern file and rename every uniquely matching symbol#Import and Rename Symbols...:B:0:::>\n";

template<typename T>
static T GetNetnodeValue(const char* p_Name, T p_DefaultVal)
{
	T s_Value;
	netnode s_Node(p_Name, 0, true);

	if (s_Node.valobj(&s_Value, sizeof(T)) != sizeof(T))
		return p_DefaultVal;

	return s_Value;
}

template<typename T>
static void SetNetnodeValue(const char* p_Name, T p_Value)
{
	netnode s_Node(p_Name, 0, true);
	s_Node.set(&p_Value, sizeof(T));
}

#ifdef _WIN32
static void CopyToClipboard(const std::string& p_Text)
{
	if (!OpenClipboard(nullptr))
		return;

	EmptyClipboard();

	HGLOBAL s_ClipboardBlob = GlobalAlloc(GMEM_MOVEABLE, p_Text.size() + 1);
	if (s_ClipboardBlob != nullptr)
	{
		char* s_Locked = reinterpret_cast<char*>(GlobalLock(s_ClipboardBlob));
		if (s_Locked != nullptr)
		{
			strcpy_s(s_Locked, p_Text.size() + 1, p_Text.c_str());
			GlobalUnlock(s_ClipboardBlob);

			if (SetClipboardData(CF_TEXT, s_ClipboardBlob) == nullptr)
				GlobalFree(s_ClipboardBlob);
		}
		else
		{
			GlobalFree(s_ClipboardBlob);
		}
	}

	CloseClipboard();
}
#else
#include <cstdio>

static bool PipeToCommand(const char* p_Command, const std::string& p_Text)
{
	FILE* s_Pipe = popen(p_Command, "w");
	if (s_Pipe == nullptr)
		return false;

	const size_t s_Written = qfwrite(s_Pipe, p_Text.data(), p_Text.size());
	const int    s_Status  = pclose(s_Pipe);

	return s_Written == p_Text.size() && s_Status == 0;
}

static void CopyToClipboard(const std::string& p_Text)
{
	// Try a sequence of common clipboard helpers. Errors from missing tools are
	// silenced by redirecting stderr; popen() itself only fails if /bin/sh is missing.
	static const char* const s_Candidates[] =
	{
#ifdef __APPLE__
		"pbcopy 2>/dev/null",
#endif
		"wl-copy 2>/dev/null",
		"xclip -selection clipboard 2>/dev/null",
		"xsel --clipboard --input 2>/dev/null",
		nullptr,
	};

	for (const char* const* s_Cmd = s_Candidates; *s_Cmd != nullptr; ++s_Cmd)
	{
		if (PipeToCommand(*s_Cmd, p_Text))
			return;
	}

	msg("[SigMe] Could not copy to clipboard: install xclip, xsel, or wl-clipboard.\n");
}
#endif

static int idaapi ExportButtonCallback(int /*button_code*/, form_actions_t& /*fa*/)
{
	ExportRenamedSymbols();
	return 0;
}

static int idaapi ImportButtonCallback(int /*button_code*/, form_actions_t& /*fa*/)
{
	ImportAndRenameSymbols();
	return 0;
}

static bool idaapi IDAP_run(size_t /*arg*/)
{
	PLUGIN.flags |= PLUGIN_UNL;

	// Load our saved settings (if any).
	uval_t s_WildcardByte   = GetNetnodeValue<uint8_t>("$ sigme_wb", 0xDD);
	ushort s_SelectedMethod = GetNetnodeValue<uint8_t>("$ sigme_sm", 0);
	ushort s_CheckMask      = GetNetnodeValue<uint8_t>("$ sigme_cm", 2);

	// Show our main form.
	if (ask_form(g_SelectionDialog, &s_SelectedMethod, &s_WildcardByte, &s_CheckMask,
	             ExportButtonCallback, ImportButtonCallback) != 1)
		return false;

	// Store the new setting values in the IDB.
	SetNetnodeValue<uint8_t>("$ sigme_wb", (uint8_t) s_WildcardByte);
	SetNetnodeValue<uint8_t>("$ sigme_sm", (uint8_t) s_SelectedMethod);
	SetNetnodeValue<uint8_t>("$ sigme_cm", (uint8_t) s_CheckMask);

	bool s_Unique    = (s_CheckMask & 1) != 0;
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
	msg("[SigMe] Generated signature (%d bytes):\n%s\n",
	    (int) s_Scanner.GetSignatureLength(), s_Signature.c_str());

	if (s_Clipboard)
		CopyToClipboard(s_Signature);

	return true;
}

static void idaapi IDAP_term(void)
{
}

static plugmod_t* idaapi IDAP_init(void)
{
	return PLUGIN_KEEP;
}
