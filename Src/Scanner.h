#pragma once

#pragma warning(push)
#pragma warning(disable: 4244 4267)
#include <idp.hpp>
#pragma warning(pop)

#include <vector>
#include <sstream>

class Scanner
{
public:
	struct SigByte
	{
		SigByte(uint8_t p_Byte, bool p_Masked = false) :
			m_Byte(p_Byte), m_Masked(p_Masked)
		{
		}

		uint8_t m_Byte;
		bool m_Masked;
	};

	enum SigType
	{
		IDA,
		C,
		SourceMod,
		Custom
	};

public:
	Scanner(ea_t p_StartAddress, bool p_Unique);

public:
	void StartScanning();
	std::string GetSignature(SigType p_Type);
	size_t GetSignatureLength();
	inline bool HasError() const { return m_HasError; }

private:
	void ProcessInstruction();
	bool HasSignature();
	void AddSigByte(SigByte p_Byte);
	void AddSigBytes(const std::vector<SigByte>& p_Byte);

	std::string GetIDASignature();
	std::string GetFinalIDASignature();
	std::string GetCSignature();
	std::string GetSourceModSignature();
	std::string GetCustomSignature();
	std::string GetMaskedSignature(const std::string& p_MaskByte);

private:
	ea_t m_StartAddress;
	ea_t m_CurrentAddress;
	bool m_HasError;
	bool m_Unique;
	std::vector<SigByte> m_Signature;
	std::stringstream m_SignatureStream;
};