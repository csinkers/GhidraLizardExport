package lizardexport;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.util.StringUtilities;

/**
 * This class is used to convert a C language
 * token group into readable C code.
 */
public class LizardPrettyPrinter {
	/**
	 * The indent string to use when printing.
	 */
	public final static String INDENT_STRING = " ";

	private Function function;
	private ClangTokenGroup tokgroup;
	private ArrayList<ClangLine> lines = new ArrayList<ClangLine>();

	/**
	 * Constructs a new pretty printer using the specified C language token group.
	 * @param tokgroup the C language token group
	 */
	public LizardPrettyPrinter(Function function, ClangTokenGroup tokgroup) {
		this.function = function;
		this.tokgroup = tokgroup;
		this.lines = DecompilerUtils.toLines(tokgroup);

        for (ClangLine line : lines) {
			ArrayList<ClangToken> tokenList = line.getAllTokens();
			if (tokenList.size() == 0) {
				ClangToken spacer = ClangToken.buildSpacer(null, line.getIndent(), INDENT_STRING);
				spacer.setLineParent(line);
                tokenList.add(0, spacer);
			}
		}
    }

	public Function getFunction() {
		return function;
	}

	/**
	 * Returns an array list of the C language lines contained in the
	 * C language token group.
	 * @return an array list of the C language lines
	 */
	public ArrayList<ClangLine> getLines() {
		return lines;
	}

	/**
	 * Prints the C language token group
	 * into a string of C code.
	 * @param removeInvalidChars true if invalid character should be
	 * removed from functions and labels.
	 * @return a string of readable C code
	 */
	public DecompiledFunction print(boolean removeInvalidChars) {
		StringBuffer buff = new StringBuffer();

		for (ClangLine line : lines) {
			buff.append(line.getIndentString());
			List<ClangToken> tokens = line.getAllTokens();

			for (ClangToken token : tokens) {
				boolean isToken2Clean = token instanceof ClangFuncNameToken ||
										token instanceof ClangVariableToken ||
										token instanceof ClangTypeToken ||
										token instanceof ClangFieldToken ||
										token instanceof ClangLabelToken;

				//do not clean constant variable tokens
				if (isToken2Clean && token.getSyntaxType() == ClangToken.CONST_COLOR) {
					isToken2Clean = false;
				}

				if (removeInvalidChars && isToken2Clean) {
					String tokenText = token.getText();
					for (int i = 0 ; i < tokenText.length() ; ++i) {
						if (StringUtilities.isValidCLanguageChar(tokenText.charAt(i))) {
							buff.append(tokenText.charAt(i));
						}
						else {
							buff.append('_');
						}
					}
				}
				else {
					buff.append(token.getText());
				}
			}
			buff.append(StringUtilities.LINE_SEPARATOR);
		}
		return new DecompiledFunction(findSignature(), buff.toString());
	}

	public String getOffsetsLine() {
		StringBuffer sb = new StringBuffer();
		long baseOffset = function.getEntryPoint().getOffset();
		sb.append("//!L! ");
		sb.append(String.format("%08x", baseOffset));
		sb.append(" ");

		int[] minima = new int[lines.size()];

		for (int i = 0; i < lines.size(); i++) {
			var line = lines.get(i);
			List<ClangToken> tokens = line.getAllTokens();
			long min = Long.MAX_VALUE;
			long max = 0;

			for (ClangToken token : tokens) {
				var tminAddr = token.getMinAddress();
				var tmaxAddr = token.getMaxAddress();
				if (tminAddr == null || tmaxAddr == null) continue;

				var tmin = tminAddr.getOffset();
				var tmax = tmaxAddr.getOffset();
				if (tmin < min) min = tmin;
				if (tmax > max) max = tmax;
			}

			minima[i] =
				(min != Long.MAX_VALUE && max != 0)
				? (int)min
				: (int)(i > 0 ? minima[i-1] : baseOffset);
		}

		int[] offsets = PackedBase64Offsets.ConvertToOffsets((int)baseOffset, minima);
		sb.append(PackedBase64Offsets.Encode(offsets));
		return sb.toString();
	}

	static int operandSize(int operandType) {
		if (OperandType.isByte(operandType)) return 1;
		if (OperandType.isWord(operandType)) return 2;
		if (OperandType.isQuadWord(operandType)) return 8;
		return 4;
	}

	Integer getBaseOffset() {
		int stackOffset = 0;
		AddressSetView body = function.getBody();
		Listing listing = function.getProgram().getListing();
		InstructionIterator iterator = listing.getInstructions(body, true);

		for (Instruction instruction : iterator) {
			var asString = instruction.toString();
			var mnemonic = instruction.getMnemonicString();
			switch (mnemonic)
			{
			case "PUSH":
				int operandType = instruction.getOperandType(0);
				if (OperandType.isScalar(operandType) && stackOffset == 0)
				{
					stackOffset += operandSize(operandType);
				}
				else if (OperandType.isRegister(operandType))
				{
					if (asString.equals("PUSH EBP"))
						return stackOffset;

					stackOffset += operandSize(operandType);
				}
				else return null; // Unexpected

			case "CALL":
				break;

			case "MOV":
				if (asString.equals("MOV EBP, ESP"))
					break;

				return null;

			case "SUB":
				if (asString.startsWith("SUB ESP, "))
					break;

				return null;

			default: return null; // Give up if we see anything unexpected
			}
		}

		return null;

		/*
		Expected prologue:
        68 xxxxxxxx    PUSH maxFrameSize                   104
        e8 0e 1e 07 00 CALL StackGuard                     232 14 30 7 0 = -24 14 30 7 0 (actually -24 57 24 7 0)
        5x             [PUSH registersToBeSaved]           80-95
        55             PUSH EBP                            85
        89 e5          MOV EBP, ESP                        137 229 = -119 -27
        81 ec xxxxxxxx SUB ESP, <sizeOfLocals> (can be 0!) 129 236 = -127 -20

        Save order: EBX, ECX, EDX, ESI, EDI
        Params: EAX, EDX, EBX, ECX, stack

		Epilogue:
        89 ec MOV ESP, EBP (elided when 0 locals)
        5d    POP EBP
        5x    [POP registersToBeSaved]
        c3    RET
		 */
	}

	public String getBaseOffsetLine() {
		Integer baseOffset = getBaseOffset();
		if (baseOffset == null)
			return null;

		StringBuffer sb = new StringBuffer();
		sb.append("//!B! " + baseOffset.toString());
		return sb.toString();
	}

	private String findSignature() {
		int nChildren = tokgroup.numChildren();
		for (int i = 0; i < nChildren; ++i) {
			ClangNode node = tokgroup.Child(i);
			if (node instanceof ClangFuncProto) {
				return node.toString() + ";";
			}
		}
		return null;
	}
}

