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

import java.io.*;
import java.util.*;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.QCallback;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileOptions.CommentStyleEnum;
import ghidra.app.decompiler.parallel.ChunkingParallelDecompiler;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import ghidra.util.task.TaskMonitor;

/**
 * Exports the program database as a C file containing per-line address info.
 * Mostly based on the default CppExporter with line address offset info added and various options removed.
 */
public class LizardExporter extends Exporter {

	private static String EOL = System.getProperty("line.separator");
	private DecompileOptions options;

	/**
	 * Exporter constructor.
	 */
	public LizardExporter() 
	{
		super("C for Lizard Debugger", "c", null); // Name & extension
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws IOException, ExporterException 
	{
		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}

		Program program = (Program)domainObj;
		configureOptions(program);

		if (addrSet == null) {
			addrSet = program.getMemory();
		}

		PrintWriter cFileWriter = new PrintWriter(file);
		CachingPool<DecompInterface> decompilerPool = new CachingPool<>(new DecompilerFactory(program));
		ParallelDecompilerCallback callback = new ParallelDecompilerCallback(decompilerPool);
		ChunkingTaskMonitor chunkingMonitor = new ChunkingTaskMonitor(monitor);
		ChunkingParallelDecompiler<CPPResult> parallelDecompiler = ParallelDecompiler.createChunkingParallelDecompiler(callback, chunkingMonitor);

		try {
			chunkingMonitor.checkCanceled();
			decompileAndExport(addrSet, program, cFileWriter, parallelDecompiler, chunkingMonitor);
			return true;
		}
		catch (CancelledException e) {
			return false;
		}
		catch (Exception e) {
			Msg.error(this, "Error exporting C/C++", e);
			return false;
		}
		finally {
			decompilerPool.dispose();
			parallelDecompiler.dispose();
			cFileWriter.close();
		}
	}

	@Override public List<Option> getOptions(DomainObjectService domainObjectService) { return new ArrayList<>(); }
	@Override public void setOptions(List<Option> options) throws OptionException { }

	private void decompileAndExport(AddressSetView addrSet, Program program,
			PrintWriter cFileWriter, ChunkingParallelDecompiler<CPPResult> parallelDecompiler,
			ChunkingTaskMonitor chunkingMonitor)
			throws InterruptedException, Exception, CancelledException 
	{
		int functionCount = program.getFunctionManager().getFunctionCount();
		chunkingMonitor.doInitialize(functionCount);

		Listing listing = program.getListing();
		FunctionIterator iterator = listing.getFunctions(addrSet, true);
		List<Function> functions = new ArrayList<>();
		for (int i = 0; iterator.hasNext(); i++) {
			//
			// Write results every so many items so that we don't blow out memory
			//
			if (i % 10000 == 0) {
				List<CPPResult> results = parallelDecompiler.decompileFunctions(functions);
				writeResults(results, cFileWriter, chunkingMonitor);
				functions.clear();
			}

			Function currentFunction = iterator.next();
			functions.add(currentFunction);
		}

		// handle any remaining functions
		List<CPPResult> results = parallelDecompiler.decompileFunctions(functions);
		writeResults(results, cFileWriter, chunkingMonitor);
	}

	private void writeResults(List<CPPResult> results, PrintWriter cFileWriter, TaskMonitor monitor) throws CancelledException
	{
		monitor.checkCanceled();

		Collections.sort(results);

		StringBuilder bodies = new StringBuilder();
		for (CPPResult result : results) {
			monitor.checkCanceled();
			if (result == null) {
				continue;
			}

			String bodyCode = result.getBodyCode();
			if (bodyCode != null) {
				bodies.append(bodyCode);
				bodies.append(EOL);
			}
		}

		monitor.checkCanceled();
		cFileWriter.print(bodies.toString());
	}

	private void configureOptions(Program program) {
		options = new DecompileOptions();

		if (provider != null) {
			OptionsService service = provider.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		else {
			options.grabFromProgram(program);	// Let headless pull program specific options
		}

		options.setCommentStyle(CommentStyleEnum.CPPStyle);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CPPResult implements Comparable<CPPResult> {

		private Address address;
		private String bodyCode;

		CPPResult(Address address, String bodyCode) {
			this.address = address;
			this.bodyCode = bodyCode;
		}

		String getBodyCode() {
			return bodyCode;
		}

		@Override
		public int compareTo(CPPResult other) {
			return address.compareTo(other.address);
		}

	}

	private class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

		private Program program;

		DecompilerFactory(Program program) {
			this.program = program;
		}

		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {
			DecompInterface decompiler = new DecompInterface();
			decompiler.setOptions(options);
			decompiler.openProgram(program);
            // Note: the default exporter disables the syntax tree, but we need it for getting the address mapping
			return decompiler;
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}

	private class ParallelDecompilerCallback implements QCallback<Function, CPPResult> {

		private CachingPool<DecompInterface> pool;

		ParallelDecompilerCallback(CachingPool<DecompInterface> decompilerPool) {
			this.pool = decompilerPool;
		}

		@Override
		public CPPResult process(Function function, TaskMonitor monitor) throws Exception {
			if (monitor.isCancelled()) {
				return null;
			}

			DecompInterface decompiler = pool.get();
			try {
				CPPResult result = doWork(function, decompiler, monitor);
				return result;
			}
			finally {
				pool.release(decompiler);
			}
		}

		private CPPResult doWork(Function function, DecompInterface decompiler, TaskMonitor monitor) {
			Address entryPoint = function.getEntryPoint();
			CodeUnit codeUnitAt = function.getProgram().getListing().getCodeUnitAt(entryPoint);
			if (codeUnitAt == null || !(codeUnitAt instanceof Instruction)) {
				return new CPPResult(entryPoint, null);
			}

			monitor.setMessage("Decompiling " + function.getName());

			DecompileResults dr = decompiler.decompileFunction(function, options.getDefaultTimeout(), monitor);
			String errorMessage = dr.getErrorMessage();
			if (errorMessage != null && errorMessage.length() > 0 && EOL != "\n") {
				errorMessage = errorMessage.replace("\n", EOL);
			}

			if (!"".equals(errorMessage)) {
				Msg.warn(LizardExporter.this, "Error decompiling: " + errorMessage);
				if (options.isWARNCommentIncluded()) {
					monitor.incrementProgress(1);
					return new CPPResult(entryPoint,
						"/*" + EOL + "Unable to decompile '" + function.getName() + "'" + EOL +
							"Cause: " + errorMessage + EOL + "*/" + EOL);
				}
				return null;
			}

			ClangTokenGroup docroot = dr.getCCodeMarkup();
			LizardPrettyPrinter printer = new LizardPrettyPrinter(dr.getFunction(), docroot);
			String offsetsLine = printer.getOffsetsLine();
			DecompiledFunction decompiledFunction = printer.print(true);

			return new CPPResult(entryPoint, offsetsLine + System.lineSeparator() + decompiledFunction.getC());
		}
	}

	/**
	 * A class that exists because we are doing something that the ConcurrentQ was not
	 * designed for--chunking.  We do not want out monitor being reset every time we start a new
	 * chunk. So, we wrap a real monitor, overriding the behavior such that initialize() has
	 * no effect when it is called by the queue.
	 */
	private class ChunkingTaskMonitor extends TaskMonitorAdapter {
		private TaskMonitor monitor;

		ChunkingTaskMonitor(TaskMonitor monitor) { this.monitor = monitor; }
		void doInitialize(long value) { monitor.initialize(value); } // this lets us initialize when we want to
		@Override public void setProgress(long value) { monitor.setProgress(value); } 
		@Override public void checkCanceled() throws CancelledException { monitor.checkCanceled(); } 
		@Override public void setMessage(String message) { monitor.setMessage(message); } 
		@Override public synchronized void addCancelledListener(CancelledListener listener) { monitor.addCancelledListener(listener); } 
		@Override public synchronized void removeCancelledListener(CancelledListener listener) { monitor.removeCancelledListener(listener); }
	}
}

