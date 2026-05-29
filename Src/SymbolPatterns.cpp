#include "SymbolPatterns.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4244 4267)
#endif
#include <ida.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <search.hpp>
#include <xref.hpp>
#include <fpro.h>
#include <kernwin.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "Scanner.h"

#include <string>

// Separator between fields in the pattern file.
// Signatures only contain hex digits, '?' and spaces, so '|' is unambiguous.
static const char g_FieldSeparator = '|';

// Entry kinds written as the first field of each line.
//   F = function: the signature points at the symbol itself.
//   G = global  : the signature points at the first code reference to the
//                 symbol; on import the referenced data address is renamed.
static const char g_KindFunction = 'F';
static const char g_KindGlobal   = 'G';

static std::string TrimTrailingSpaces(const std::string& p_Text)
{
	size_t s_End = p_Text.find_last_not_of(" \t\r\n");
	if (s_End == std::string::npos)
		return "";

	return p_Text.substr(0, s_End + 1);
}

// Returns the first address that references p_Address from code, or BADADDR.
static ea_t FindFirstCodeReference(ea_t p_Address)
{
	for (ea_t s_Ref = get_first_dref_to(p_Address); s_Ref != BADADDR; s_Ref = get_next_dref_to(p_Address, s_Ref))
	{
		if (is_code(get_flags(s_Ref)))
			return s_Ref;
	}

	return BADADDR;
}

void ExportRenamedSymbols()
{
	char* s_Path = ask_file(true, "*.sigme", "SigMe: export renamed symbol patterns");
	if (s_Path == nullptr)
		return;

	FILE* s_File = qfopen(s_Path, "w");
	if (s_File == nullptr)
	{
		msg("[SigMe] Could not open '%s' for writing.\n", s_Path);
		return;
	}

	qfputs("# SigMe symbol patterns: <kind>|<IDA signature>|<name>\n", s_File);

	size_t s_Exported = 0;
	size_t s_Skipped  = 0;

	const size_t s_Count = get_nlist_size();
	for (size_t i = 0; i < s_Count; ++i)
	{
		ea_t s_Address = get_nlist_ea(i);

		// Only export symbols the user explicitly named.
		if (!has_user_name(get_flags(s_Address)))
			continue;

		const char* s_Name = get_nlist_name(i);
		if (s_Name == nullptr || s_Name[0] == '\0')
			continue;

		// Functions are signed directly. Globals (data) cannot be decoded into
		// instructions, so we sign their first code reference instead and record
		// enough to recover the data address on import.
		char s_Kind        = g_KindFunction;
		ea_t s_SignatureEa = s_Address;

		if (!is_func(get_flags(s_Address)))
		{
			ea_t s_Reference = FindFirstCodeReference(s_Address);
			if (s_Reference == BADADDR)
			{
				++s_Skipped;
				continue;
			}

			s_Kind        = g_KindGlobal;
			s_SignatureEa = s_Reference;
		}

		// Generate a database-wide unique signature so it can be matched again.
		Scanner s_Scanner(s_SignatureEa, true);
		s_Scanner.StartScanning();

		if (s_Scanner.HasError())
		{
			++s_Skipped;
			continue;
		}

		std::string s_Signature = TrimTrailingSpaces(s_Scanner.GetSignature(Scanner::IDA));
		if (s_Signature.empty())
		{
			++s_Skipped;
			continue;
		}

		std::string s_Line = std::string(1, s_Kind) + g_FieldSeparator + s_Signature
		                   + g_FieldSeparator + s_Name + "\n";
		qfputs(s_Line.c_str(), s_File);
		++s_Exported;
	}

	qfclose(s_File);

	msg("[SigMe] Exported %d symbol pattern(s) to '%s' (%d skipped).\n",
	    (int) s_Exported, s_Path, (int) s_Skipped);
}

void ImportAndRenameSymbols()
{
	char* s_Path = ask_file(false, "*.sigme", "SigMe: import symbol patterns");
	if (s_Path == nullptr)
		return;

	FILE* s_File = qfopen(s_Path, "r");
	if (s_File == nullptr)
	{
		msg("[SigMe] Could not open '%s' for reading.\n", s_Path);
		return;
	}

	const ea_t s_MinEa = inf_get_min_ea();
	const ea_t s_MaxEa = inf_get_max_ea();

	size_t s_Renamed   = 0;
	size_t s_NotFound  = 0;
	size_t s_Ambiguous = 0;
	size_t s_Failed    = 0;

	qstring s_LineBuf;
	while (qgetline(&s_LineBuf, s_File) >= 0)
	{
		std::string s_Line(s_LineBuf.c_str());

		// Skip comments and blank lines.
		if (s_Line.empty() || s_Line[0] == '#')
			continue;

		// Expected layout: <kind>|<signature>|<name>.
		size_t s_FirstSep = s_Line.find(g_FieldSeparator);
		if (s_FirstSep == std::string::npos)
			continue;

		size_t s_SecondSep = s_Line.find(g_FieldSeparator, s_FirstSep + 1);
		if (s_SecondSep == std::string::npos)
			continue;

		std::string s_KindField = TrimTrailingSpaces(s_Line.substr(0, s_FirstSep));
		std::string s_Signature = TrimTrailingSpaces(s_Line.substr(s_FirstSep + 1, s_SecondSep - s_FirstSep - 1));
		std::string s_Name       = TrimTrailingSpaces(s_Line.substr(s_SecondSep + 1));

		if (s_KindField.size() != 1 || s_Signature.empty() || s_Name.empty())
			continue;

		const char s_Kind = s_KindField[0];

		// Search the entire database for the pattern.
		ea_t s_Found = find_binary(s_MinEa, s_MaxEa, s_Signature.c_str(), 16, BIN_SEARCH_FORWARD);
		if (s_Found == BADADDR)
		{
			++s_NotFound;
			continue;
		}

		// Reject patterns that match more than one location.
		ea_t s_Second = find_binary(s_Found + 1, s_MaxEa, s_Signature.c_str(), 16, BIN_SEARCH_FORWARD);
		if (s_Second != BADADDR)
		{
			++s_Ambiguous;
			continue;
		}

		// For globals the signature points at a referencing instruction; resolve
		// the data address it refers to and rename that instead.
		ea_t s_Target = s_Found;
		if (s_Kind == g_KindGlobal)
		{
			s_Target = get_first_dref_from(s_Found);
			if (s_Target == BADADDR)
			{
				++s_Failed;
				continue;
			}
		}

		if (set_name(s_Target, s_Name.c_str(), SN_NOCHECK | SN_FORCE))
			++s_Renamed;
		else
			++s_Failed;
	}

	qfclose(s_File);

	msg("[SigMe] Import complete: %d renamed, %d not found, %d ambiguous, %d failed.\n",
	    (int) s_Renamed, (int) s_NotFound, (int) s_Ambiguous, (int) s_Failed);
}
