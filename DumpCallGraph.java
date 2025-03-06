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
 *
 * Adapted from ExportFunctionInfoScript.java, inspired by
 * Christopher Robert's Firmware Slap
 */
// List function names and verbose metadata to a file in JSON format
//@category Functions

// Headless invocation:
/*
~/Downloads/ghidra_11.2.1_PUBLIC/support/analyzeHeadless /PATH/TO/GHIDRA/PROJECT GHIDRA_PROJECT 
-process layers.bin
-postScript  ExportFunctionInfoScriptVerbose.java 
-scriptPath /PATH/TO/THIS/SCRIPT 
-readOnly 
*/

import java.io.FileWriter;
import java.util.ArrayList;
import java.io.File;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighSymbol;

import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DumpCallGraph extends GhidraScript {

	//==========================================================================
	private void autoCommitParameters(DecompInterface ifc, Program p, Function f, int timeout){
		/*
		Students are not expected to do this, but included as bonus content.
		Adapted from the Ghidra API Docs
		*/
	
		// Make calls to the decompiler:
		DecompileResults res = ifc.decompileFunction(f,0, null);
		
		// Check for error conditions
		if (!res.decompileCompleted()) {
			println(res.getErrorMessage());
			return;
		}
		
		// Make use of results
		// Get C code
		// Get the function object/syntax tree
		HighFunction hfunc = res.getHighFunction();
		FunctionPrototype functionPrototype = hfunc.getFunctionPrototype();	

		printf("%s() signature: %s\n", f.getName(), functionPrototype.getReturnType().toString());
		for (int i = 0; i < functionPrototype.getNumParams(); i++) {
			HighSymbol parameter = functionPrototype.getParam(i);
			printf("%s\n",parameter.getDataType().toString() + " " + parameter.getName());
		}


		try{
			HighFunctionDBUtil.commitParamsToDatabase(hfunc, true, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.ANALYSIS);
			//HighFunctionDBUtil.commitReturnToDatabase(hfunc, SourceType.ANALYSIS);
			//HighFunctionDBUtil.commitParamsToDatabase(hfunc, true, SourceType.ANALYSIS);		
		}
		catch(DuplicateNameException | InvalidInputException e){
			println(e.toString());
		}
	}

	//==========================================================================
	private JsonElement getCallingFunctions(Function f, Gson gson){

		ArrayList<String> stringList = new ArrayList<String>();
		for (Function f2: f.getCallingFunctions(null)){
			stringList.add(f2.getName());
		}
		String[] callingFunctionsList = stringList.toArray(new String[stringList.size()]);		
		JsonElement je = gson.toJsonTree(callingFunctionsList);
		return je;
	}
	//==========================================================================
	private JsonElement getCalledFunctions(Function f, Gson gson){

		ArrayList<String> stringList = new ArrayList<String>();
		for (Function f2: f.getCalledFunctions(null)){
			stringList.add(f2.getName());
		}
		String[] callingFunctionsList = stringList.toArray(new String[stringList.size()]);		
		JsonElement je = gson.toJsonTree(callingFunctionsList);
		return je;
	}	
	
	//==========================================================================
	@Override
	public void run() throws Exception {

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		DecompInterface ifc = null;

		//File outputFile = askFile("Please Select Output File", "Choose");
		//JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));

		Boolean autoCommitBool = true;
		int timeout = 30;
		String autoCommitString = askString("Commit function parameters",
									"Would you like to commit function parameter value and return? This is recommended, otherwise the results of this script may not match the decompiled view in the GUI. [y/Y/]",
									"y");
		if(autoCommitString.equals("y") || autoCommitString.equals("Y")){
			printf("Will commit commit function parameter and returns.\n");
			ifc = new DecompInterface();			
			// Setup any options or other initialization
			//ifc.setOptions(xmlOptions); // Inform interface of global options
			// ifc.toggleSyntaxTree(false);  // Don't produce syntax trees
			// ifc.toggleCCode(false);       // Don't produce C code
			// ifc.setSimplificationStyle("normalize"); // Alternate analysis style
			
			// Setup up the actual decompiler process for a
			// particular program, using all the above initialization
			ifc.openProgram(currentProgram);			
		}


		String defaultFileName = "./graph_a.json";
		String outputFile = askString("Output", "Please provide name of file for output:", defaultFileName);
		JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile));
		
		jsonWriter.beginArray();

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);


		while (iter.hasNext() && !monitor.isCancelled()) {
			printf("-------------------------------------\n");

			Function f = iter.next();

			if (autoCommitBool){;
				//printf("Commit params for %s\n", f.getName());
				autoCommitParameters(ifc, currentProgram, f, timeout);
			}

			String name = f.getName();

			// These were already in ExportFunctionInfoScript
			JsonObject json = new JsonObject();
			json.add(name, getCalledFunctions(f, gson));

			gson.toJson(json, jsonWriter);
		}

		jsonWriter.endArray();
		jsonWriter.close();

		printf("Wrote function metadata to %s (CWD+%s)\n", outputFile, new File("").getAbsolutePath());	
	}
}
