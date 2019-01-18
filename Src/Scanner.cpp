#include "Scanner.h"

#include <search.hpp>

#include <iomanip>

Scanner::Scanner(ea_t p_StartAddress, bool p_Unique) : 
	m_StartAddress(p_StartAddress), 
	m_CurrentAddress(p_StartAddress),
	m_HasError(false),
	m_Unique(p_Unique)
{
}

void Scanner::StartScanning()
{
	while (!HasSignature())
		ProcessInstruction();

	// Remove masked bytes from back.
	for (size_t i = m_Signature.size() - 1; i >= 0; --i)
	{
		if (!m_Signature[i].m_Masked)
			break;

		m_Signature.pop_back();
	}

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
	insn_t s_Instruction;
	memset(&s_Instruction, 0x00, sizeof(insn_t));

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

	// If we don't care about total uniqueness then search for our current pattern only
	// up to the beginning of our searching area.
	if (!m_Unique)
		return find_binary(inf.min_ea, m_StartAddress, GetIDASignature().c_str(), 16, 1) == BADADDR;
	
	// Otherwise search the entire database and see if our instance is totally unique.
	ea_t s_FoundAddress = find_binary(inf.min_ea, inf.max_ea, GetIDASignature().c_str(), 16, 1);
	ea_t s_SecondFound = find_binary(m_StartAddress + 1, inf.max_ea, GetIDASignature().c_str(), 16, 1);

	return s_FoundAddress == BADADDR || (s_FoundAddress == m_StartAddress && s_SecondFound == BADADDR);
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

	s_Stream << GetMaskedSignature("00");

	// Add the mask.
	s_Stream << std::endl;

	for (auto s_Byte : m_Signature)
		s_Stream << (s_Byte.m_Masked ? "?" : "x");

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
