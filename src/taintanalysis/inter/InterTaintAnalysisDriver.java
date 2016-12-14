package taintanalysis.inter;

import soot.Pack;
import soot.PackManager;
import soot.PhaseOptions;
import soot.SootClass;
import soot.SootResolver;
import soot.Transform;
import soot.options.Options;

public class InterTaintAnalysisDriver {
	public static void main(String[] args) {
		if(args.length==0) {
			System.err.println("ERROR: No input file");
			System.exit(0);
		}
		
		// apply some options to the soot
		// option specifying soot to use original variable names
		Options.v().setPhaseOption("jb", "use-original-names:true");
		// option specifying soot to keep line numbers from java source file 
		Options.v().set_keep_line_number(true);
		// option specifying to use whole program (-w) option
		Options.v().set_whole_program(true);
		// option specifying soot to produce Jimple file as output
		Options.v().set_output_format(Options.output_format_jimple);
		// option specifying main java class file to analyze
		Options.v().set_main_class(args[0]);
		PhaseOptions.v().setPhaseOption( "cg.spark", "enabled" );
		PhaseOptions.v().setPhaseOption( "cg.spark", "rta" );
		
		// add a phase to transformer pack by calling Pack.add
		Pack jtp = PackManager.v().getPack("jtp");
		jtp.add(new Transform("jtp.instrumenter", new InterTaintAnalysisWrapper(args[0])));
		
		// resolves the given class
		SootResolver.v().resolveClass("java.lang.CloneNotSupportedException", SootClass.SIGNATURES);
		
		// give control to Soot to process all options
	    // TaintAnalysisWrapper.internalTransform will get called
		soot.Main.main(args);
	}
}