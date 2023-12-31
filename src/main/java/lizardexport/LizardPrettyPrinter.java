package lizardexport;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.listing.Function;
import ghidra.util.StringUtilities;
import ghidra.util.datastruct.IntArrayList;

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
	private IntArrayList linesOffsets = new IntArrayList();
	private long functionOffset;

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

	private String findSignature() {
		int nChildren = tokgroup.numChildren();
		for (int i = 0 ; i < nChildren ; ++i) {
			ClangNode node = tokgroup.Child(i);
			if (node instanceof ClangFuncProto) {
				return node.toString()+";";
			}
		}
		return null;
	}
}

