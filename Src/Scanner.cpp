#include "Scanner.h"

#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <search.hpp>

#include <iomanip>

Scanner::Scanner(ea_t p_StartAddress, bool p_Unique) : 
	m_StartAddress(p_StartAddress), 
	m_CurrentAddress(p_StartAddress),
	m_StartFuncStart(BADADDR),
	m_MinEa(inf_get_min_ea()),
	m_MaxEa(inf_get_max_ea()),
	m_HasError(false),
	m_Unique(p_Unique)
{
	// Remember which function we started in (if any) so we can stop before
	// crossing into a different function.
	func_t* s_Func = get_func(p_StartAddress);
	if (s_Func != nullptr)
		m_StartFuncStart = s_Func->start_ea;
}

void Scanner::StartScanning()
{
	while (!HasSignature())
		ProcessInstruction();

	// Remove masked bytes from back.
	while (!m_Signature.empty() && m_Signature.back().m_Masked)
		m_Signature.pop_back();

	// Remove masked bytes from front.
	while (m_Signature.size() > 0 && m_Signature[0].m_Masked)
		m_Signature.erase(m_Signature.begin());
}

std::string Scanner::GetSignature(SigType p_Type)
{
	switch (p_Type)
	{
	case IDA:
		return GetFinalIDASignature();

	case C:
		return GetCSignature();

	case SourceMod:
		return GetSourceModSignature();

	case Custom:
		return GetCustomSignature();

	default:
		return "";
	}
}

size_t Scanner::GetSignatureLength()
{
	if (m_HasError)
		return 0;

	return m_Signature.size();
}

void Scanner::ProcessInstruction()
{
	// Stop if we have wandered out of the function we started in.
	if (m_StartFuncStart != BADADDR)
	{
		func_t* s_CurrentFunc = get_func(m_CurrentAddress);
		if (s_CurrentFunc == nullptr || s_CurrentFunc->start_ea != m_StartFuncStart)
		{
			m_HasError = true;
			return;
		}
	}

	insn_t s_Instruction;

	int s_InstructionLen = decode_insn(&s_Instruction, m_CurrentAddress);
	
	if (s_InstructionLen == 0)
	{
		m_HasError = true;
		return;
	}

	std::vector<SigByte> s_InstructionBytes;

	for (int i = 0; i < s_InstructionLen; ++i)
		s_InstructionBytes.push_back(SigByte(get_byte(m_CurrentAddress + i)));

	// Mask out any operands.
	for (int i = 0; i < UA_MAXOP; ++i)
	{
		if (s_Instruction.ops[i].type == o_void)
			break;

		// We only care about specific types of operands.
		if (s_Instruction.ops[i].type != o_mem &&
			s_Instruction.ops[i].type != o_imm &&
			s_Instruction.ops[i].type != o_far &&
			s_Instruction.ops[i].type != o_near)
			continue;
		
		// Calculate the end offset of this operand.
		int s_OperandEnd = s_InstructionLen;

		if (i < UA_MAXOP - 1 && s_Instruction.ops[i + 1].type != o_void && s_Instruction.ops[i + 1].offb >= s_Instruction.ops[i].offb)
			s_OperandEnd = s_Instruction.ops[i + 1].offb;
		
		for (int j = s_Instruction.ops[i].offb; j < s_OperandEnd; ++j)
			s_InstructionBytes[j].m_Masked = true;
	}

	AddSigBytes(s_InstructionBytes);
	m_CurrentAddress += s_InstructionLen;
}

bool Scanner::HasSignature()
{
	if (m_HasError)
		return true;

	if (m_Signature.size() == 0)
		return false;

	const std::string s_Pattern = GetIDASignature();

	// If we don't care about total uniqueness then search for our current pattern only
	// up to the beginning of our searching area.
	if (!m_Unique)
		return find_binary(m_MinEa, m_StartAddress, s_Pattern.c_str(), 16, BIN_SEARCH_FORWARD) == BADADDR;

	// Find the earliest occurrence in the whole database. Our own bytes always
	// match at m_StartAddress, so the first match is either an earlier copy
	// (signature not yet unique) or our own instance.
	ea_t s_FirstFound = find_binary(m_MinEa, m_MaxEa, s_Pattern.c_str(), 16, BIN_SEARCH_FORWARD);

	// An earlier match means the pattern is still ambiguous; keep growing it.
	// This avoids a second full-database scan on every non-unique iteration.
	if (s_FirstFound != m_StartAddress)
		return s_FirstFound == BADADDR;

	// Our instance is the earliest match; it is unique iff nothing matches after it.
	return find_binary(m_StartAddress + 1, m_MaxEa, s_Pattern.c_str(), 16, BIN_SEARCH_FORWARD) == BADADDR;
}

void Scanner::AddSigByte(SigByte p_Byte)
{
	m_Signature.push_back(p_Byte);

	std::ios::fmtflags s_PrevFlags(m_SignatureStream.flags());

	if (p_Byte.m_Masked)
		m_SignatureStream << "?";
	else
		m_SignatureStream << std::hex << std::setfill('0') << std::setw(2) << (int) p_Byte.m_Byte;

	m_SignatureStream.flags(s_PrevFlags);

	m_SignatureStream << " ";
}

void Scanner::AddSigBytes(const std::vector<SigByte>& p_Byte)
{
	for (auto& s_Byte : p_Byte)
		AddSigByte(s_Byte);
}

std::string Scanner::GetIDASignature()
{
	m_SignatureStream.flush();
	return m_SignatureStream.str();
}

std::string Scanner::GetFinalIDASignature()
{
	std::stringstream s_Stream;

	for (auto s_Byte : m_Signature)
	{
		std::ios::fmtflags s_PrevFlags(s_Stream.flags());

		if (s_Byte.m_Masked)
			s_Stream << "?";
		else
			s_Stream << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << (int) s_Byte.m_Byte;

		s_Stream.flags(s_PrevFlags);

		s_Stream << " ";
	}

	s_Stream.flush();
	return s_Stream.str();
}

std::string Scanner::GetCSignature()
{
	std::stringstream s_Stream;

	s_Stream << "\"" << GetMaskedSignature("00") << "\", \"";

	for (auto s_Byte : m_Signature)
		s_Stream << (s_Byte.m_Masked ? "?" : "x");

	s_Stream << "\"";

	s_Stream.flush();
	return s_Stream.str();
}

std::string Scanner::GetSourceModSignature()
{
	return GetMaskedSignature("2A");
}

std::string Scanner::GetCustomSignature()
{
	return GetMaskedSignature("DD");
}

std::string Scanner::GetMaskedSignature(const std::string& p_MaskByte)
{
	std::stringstream s_Stream;

	for (auto s_Byte : m_Signature)
	{
		std::ios::fmtflags s_PrevFlags(s_Stream.flags());

		if (s_Byte.m_Masked)
			s_Stream << "\\x" << p_MaskByte;
		else
			s_Stream << "\\x" << std::hex << std::setfill('0') << std::setw(2) << std::uppercase << (int) s_Byte.m_Byte;

		s_Stream.flags(s_PrevFlags);
	}

	s_Stream.flush();
	return s_Stream.str();
}
