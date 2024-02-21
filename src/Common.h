#pragma once

	enum class EPathSegmentTypes : eipScanner::cip::CipUsint
	{
		NONE = 0x00,
		CLASS_8_BITS = 0x20,
		CLASS_16_BITS = 0x21,
		INSTANCE_8_BITS = 0x24,
		INSTANCE_16_BITS = 0x25,
		ATTRIBUTE_8_BITS = 0x30,
		ATTRIBUTE_16_BITS = 0x31,
		ANSI_EXXTENDED_SYMBOL = 0x91,
	};

	enum class SymbolClassAttributeNums : eipScanner::cip::CipUsint
	{
		ATTRIBUTE_NAME = 0x01,
		ATTRIBUTE_TYPE = 0x02,
		ATTRIBUTE_UNKNOWN_1 = 0x07,
		ATTRIBUTE_UNKNOWN_2 = 0x08,
	};

	enum class TemplateObjectAttributeNums : eipScanner::cip::CipUsint
	{
		ATTRIBUTE_STRUCUTRE_HANDLE = 0x01,
		ATTRIBUTE_TEMPLATE_MEMBER_COUNT = 0x02,
		ATTRIBUTE_TEMPLATE_OBJECT_DEFINITION_SIZE = 0x04,
		ATTRIBUTE_TEMPLATE_STRUCTURE_SIZE = 0x05,
	};


	std::vector<uint8_t> makeRockwellMessage(
		eipScanner::cip::CipUsint service, const eipScanner::cip::EPath& path,
		std::vector<eipScanner::cip::CipUsint>& sybolClassAttributes,
		EPathSegmentTypes sendAdditionalPathSegment = EPathSegmentTypes::NONE);

	std::vector<uint8_t> makeRockwellMessage(
		eipScanner::cip::CipUsint service, const eipScanner::cip::EPath& path,
		eipScanner::cip::CipUsint& sybolClassAttribute,
		EPathSegmentTypes sendAdditionalPathSegment = EPathSegmentTypes::NONE);