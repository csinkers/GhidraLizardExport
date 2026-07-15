/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package lizardexport;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.NameTransformer;
import ghidra.program.model.listing.*;
import ghidra.util.StringUtilities;

/**
 * This class is used to convert a C/C++ language token group into readable C/C++ code.
 */
public class LizardPrettyPrinter {

	private final static NameTransformer IDENTITY = new IdentityNameTransformer();

	public final static String INDENT_STRING = " ";

	private Function function;
	private ClangTokenGroup tokgroup;
	private List<ClangLine> lines = new ArrayList<>();
	private NameTransformer transformer;

	/**
	 * Constructs a new pretty printer using the specified C language token group.
	 * The printer takes a NameTransformer that will be applied to symbols, which can replace
	 * illegal characters in the symbol name for instance. A null indicates no transform is applied.
	 * @param function is the function to be printed
	 * @param tokgroup the C language token group
	 * @param transformer the transformer to apply to symbols
	 */
	public LizardPrettyPrinter(Function function, ClangTokenGroup tokgroup, NameTransformer transformer) {
		this.function = function;
		this.tokgroup = tokgroup;
		this.transformer = transformer != null ? transformer : IDENTITY;
		flattenLines();
		padEmptyLines();
	}

	private void padEmptyLines() {
		for (ClangLine line : lines) {
			List<ClangToken> tokenList = line.getAllTokens();
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
	 * Returns a list of the C language lines contained in the C language token group.
	 * @return a list of the C language lines
	 */
	public List<ClangLine> getLines() {
		return lines;
	}

	/**
	 * Prints the C language token group into a string of C code.
	 * @return a string of readable C code
	 */
	public DecompiledFunction print() {
		StringBuilder buff = new StringBuilder();
		for (ClangLine line : lines) {
			getText(buff, line, transformer);
			buff.append(StringUtilities.LINE_SEPARATOR);
		}
		return new DecompiledFunction(findSignature(), buff.toString());
	}

	private static void getText(StringBuilder buff, ClangLine line, NameTransformer transformer) {
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

			String tokenText = token.getText();
			if (isToken2Clean) {
				tokenText = transformer.simplify(tokenText);
			}
			buff.append(tokenText);
		}
	}

	/**
	 * Returns the text of the given line as seen in the UI.
	 * @param line the line
	 * @return the text
	 */
	public static String getText(ClangLine line) {
		StringBuilder buff = new StringBuilder();
		getText(buff, line, IDENTITY);
		return buff.toString();
	}

	public String getMetadataLine() {
		// Format: !M! {baseOffset:hex};{name};{lineOffsets:base64};{stackOffset:hex};{exitPoints:base64}
		StringBuffer sb = new StringBuffer();
		long baseOffset = function.getEntryPoint().getOffset();
		sb.append("//!M! ");
		sb.append(String.format("%08x", baseOffset));
		sb.append(';');
		sb.append(function.getName());
		sb.append(';');

		// Line offsets
		int[] minima = new int[lines.size()];

		// Find the minimum address for each line of code so we can build a mapping of address intervals to line numbers.
		for (int i = 0; i < lines.size(); i++) {
			ClangLine line = lines.get(i);
			List<ClangToken> tokens = line.getAllTokens();
			long min = Long.MAX_VALUE;
			long max = 0;

			for (ClangToken token : tokens) {
				Address tminAddr = token.getMinAddress();
				Address tmaxAddr = token.getMaxAddress();
				if (tminAddr == null || tmaxAddr == null) continue;

				long tmin = tminAddr.getOffset();
				long tmax = tmaxAddr.getOffset();
				if (tmin < min) min = tmin;
				if (tmax > max) max = tmax;
			}

			minima[i] =
				(min != Long.MAX_VALUE && max != 0)
				? (int)min
				: (int)(i > 0 ? minima[i-1] : baseOffset);
		}

		// Convert it to a compact base64 representation
		int[] offsets = PackedBase64Offsets.ConvertToOffsets((int)baseOffset, minima);
		sb.append(PackedBase64Offsets.Encode(offsets));
		sb.append(';');

		// Stack offset
		Integer stackOffset = getStackOffset();
		if (stackOffset != null) {
			sb.append(Integer.toString(stackOffset, 16));
		}

		sb.append(';');

		// Exit point offsets
		int[] exitPoints = getExitPoints();
		offsets = PackedBase64Offsets.ConvertToOffsets((int)baseOffset, exitPoints);
		sb.append(PackedBase64Offsets.Encode(offsets));

		return sb.toString();
	}

	static int operandSize(int operandType) {
		if (OperandType.isByte(operandType)) return 1;
		if (OperandType.isWord(operandType)) return 2;
		if (OperandType.isQuadWord(operandType)) return 8;
		return 4;
	}

	Integer getStackOffset() {
		int stackOffset = 0;
		AddressSetView body = function.getBody();
		Listing listing = function.getProgram().getListing();
		InstructionIterator iterator = listing.getInstructions(body, true);

		for (Instruction instruction : iterator) {
			String asString = instruction.toString();
			String mnemonic = instruction.getMnemonicString();
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

	int[] getExitPoints() {
		AddressSetView body = function.getBody();
		Listing listing = function.getProgram().getListing();

		List<Long> exits = new ArrayList<Long>();
		for (Instruction instruction : listing.getInstructions(body, true)) {
			if (instruction.getFlowType().isTerminal()) { // check for RET etc
				exits.add(instruction.getAddress().getOffset());
			}
		}

		int[] asArray = new int[exits.size()];
		for (int i = 0; i < asArray.length; i++)
			asArray[i] = exits.get(i).intValue();

		return asArray;
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

	private void flattenLines() {
		lines = DecompilerUtils.toLines(tokgroup);
	}
}
